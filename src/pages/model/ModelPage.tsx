import { useEffect, useRef, useState } from "react";
import { useAppData } from "../../app/data/useAppData";
import * as THREE from "three";
// @ts-ignore
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls';

const API_BASE = import.meta.env.VITE_API_BASE || '';

export function ModelPage() {
  const { data } = useAppData();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const sceneRef = useRef<THREE.Scene | null>(null);
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const selectedScan = data.scans.find(s => s.id === data.selectedT2);

  useEffect(() => {
    if (!canvasRef.current || !selectedScan) return;

    // --- 1. SETUP SCENE ---
    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x111111);
    sceneRef.current = scene;

    const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.01, 2000);
    camera.position.set(10, 10, 10);
    cameraRef.current = camera;

    const renderer = new THREE.WebGLRenderer({ canvas: canvasRef.current, antialias: true });
    const containerWidth = canvasRef.current.parentElement?.clientWidth || window.innerWidth * 0.9;
    renderer.setSize(containerWidth, 500);
    rendererRef.current = renderer;

    // Grid (Visual reference)
    const gridHelper = new THREE.GridHelper(30, 30, 0x444444, 0x111111);
    gridHelper.position.y = -0.01;
    scene.add(gridHelper);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.1;
    controlsRef.current = controls;

    // --- 2. LOADING LOGIC ---
    async function loadPointCloud(scanId: string) {
      setLoading(true);
      setError(null);

      try {
        const token = localStorage.getItem("constrack_token");
        const headers: Record<string, string> = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        // Request binary format for faster transfer
        const response = await fetch(`${API_BASE}/api/scans/${scanId}/points?format=binary`, { headers });

        if (!response.ok) {
          // Try to parse error from JSON response
          try {
            const errorData = await response.json();
            throw new Error(errorData.error || `Failed: ${response.statusText}`);
          } catch {
            throw new Error(`Failed: ${response.statusText}`);
          }
        }

        // Parse binary response
        const buffer = await response.arrayBuffer();
        const dataView = new DataView(buffer);

        // Read header
        const numPoints = dataView.getUint32(0, true); // little-endian
        const hasColors = dataView.getUint8(4) === 1;

        if (numPoints === 0) throw new Error("No points in file");

        // Read positions
        let offset = 5;
        const points: number[][] = [];
        for (let i = 0; i < numPoints; i++) {
          const x = dataView.getFloat32(offset, true); offset += 4;
          const y = dataView.getFloat32(offset, true); offset += 4;
          const z = dataView.getFloat32(offset, true); offset += 4;
          points.push([x, y, z]);
        }

        // Read colors if present
        let colors: number[][] | undefined;
        if (hasColors) {
          colors = [];
          for (let i = 0; i < numPoints; i++) {
            const r = dataView.getFloat32(offset, true); offset += 4;
            const g = dataView.getFloat32(offset, true); offset += 4;
            const b = dataView.getFloat32(offset, true); offset += 4;
            colors.push([r, g, b]);
          }
        }

        if (!points || points.length === 0) throw new Error("No points in file");

        // --- PREPARE GEOMETRY ---
        // 1. Center the raw data mathematically
        // We do NOT delete any points. We just shift them so the center is at (0,0,0)
        const geometry = new THREE.BufferGeometry();
        const positions = new Float32Array(points.length * 3);
        const colorArray = colors ? new Float32Array(points.length * 3) : null;

        // Calculate average center (Centroid) to normalize positions
        let sumX = 0, sumY = 0, sumZ = 0;
        for (let i = 0; i < points.length; i++) {
          sumX += points[i][0];
          sumY += points[i][1];
          sumZ += points[i][2];
        }
        const centerX = sumX / points.length;
        const centerY = sumY / points.length;
        const centerZ = sumZ / points.length;

        // Fill arrays (Shifting all points by the center)
        for (let i = 0; i < points.length; i++) {
          positions[i * 3] = points[i][0] - centerX;
          positions[i * 3 + 1] = points[i][1] - centerY;
          positions[i * 3 + 2] = points[i][2] - centerZ;

          if (colorArray && colors && colors[i]) {
            colorArray[i * 3] = colors[i][0];
            colorArray[i * 3 + 1] = colors[i][1];
            colorArray[i * 3 + 2] = colors[i][2];
          }
        }

        geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3));
        if (colorArray) {
          geometry.setAttribute('color', new THREE.BufferAttribute(colorArray, 3));
        }

        // 2. Scale it to fit the screen
        // We scale the whole "Floor" to be roughly 10 units wide
        geometry.computeBoundingBox();
        const box = geometry.boundingBox!;
        const maxDim = Math.max(
          box.max.x - box.min.x,
          box.max.y - box.min.y,
          box.max.z - box.min.z
        );
        const scaleFactor = 10 / maxDim;
        geometry.scale(scaleFactor, scaleFactor, scaleFactor);

        // --- MATERIAL (Dense points for realistic surface with 200k points) ---
        const material = new THREE.PointsMaterial({
          color: colorArray ? undefined : 0x00ffff,
          vertexColors: !!colorArray,
          size: 0.10,            // Point size for visualization
          sizeAttenuation: true
        });

        const pointCloud = new THREE.Points(geometry, material);
        pointCloud.name = "targetModel";

        // --- ORIENTATION FIX (The "Lifted" Fix) ---
        // Rotate -90 degrees on X. This lays a vertical "Z-up" scan flat on the floor.
        pointCloud.rotation.x = -Math.PI / 2;

        // Lift it up so it sits on the grid
        const rotatedBox = new THREE.Box3().setFromObject(pointCloud);
        const bottomY = rotatedBox.min.y;
        pointCloud.position.y = -bottomY;

        scene.add(pointCloud);

        // --- VIEW RESET ---
        // Calculate the NEW box after rotation and positioning
        // This ensures we see the whole floor, not just the center
        setTimeout(handleResetView, 100);

      } catch (err) {
        console.error(err);
        const msg = err instanceof Error ? err.message : "Error loading";
        setError(msg);
      } finally {
        setLoading(false);
      }
    }

    const animate = () => {
      requestAnimationFrame(animate);
      if (controlsRef.current) controlsRef.current.update();
      renderer.render(scene, camera);
    };
    animate();

    loadPointCloud(selectedScan.id);

    return () => {
      renderer.dispose();
      scene.clear();
    };
  }, [selectedScan]);

  const handleResetView = () => {
    if (!sceneRef.current || !cameraRef.current || !controlsRef.current) return;

    const model = sceneRef.current.getObjectByName("targetModel");
    if (!model) return;

    // Get the World Bounding Box (Handles the rotation correctly)
    const box = new THREE.Box3().setFromObject(model);
    const center = box.getCenter(new THREE.Vector3());
    const size = box.getSize(new THREE.Vector3());

    // Zoom out enough to see the widest part of the floor
    const maxDim = Math.max(size.x, size.y, size.z);
    const distance = maxDim * 1.2; // 1.2x buffer space

    // Position camera looking down at an angle
    cameraRef.current.position.set(
      center.x,
      center.y + distance, // High up
      center.z + distance  // Back a bit
    );
    cameraRef.current.lookAt(center);

    // Set orbit pivot to the center of the floor
    controlsRef.current.target.copy(center);
    controlsRef.current.update();
  };

  const handleRotate = (axis: 'x' | 'y' | 'z') => {
    if (sceneRef.current) {
      const model = sceneRef.current.getObjectByName("targetModel");
      if (model) {
        // Rotate the model in place
        model.rotation[axis] += Math.PI / 4;
      }
    }
  };

  if (!selectedScan) return <div>Select a scan</div>;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center flex-wrap gap-4">
        <div>
          <div className="text-2xl font-semibold">3D Model</div>
          <div className="text-sm muted">Viewing: {selectedScan.name}</div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={handleResetView}
            className="px-3 py-1.5 bg-green-600 text-white rounded hover:bg-green-700 text-sm font-medium"
          >
            Reset View
          </button>
          <button onClick={() => handleRotate('x')} className="px-3 py-1.5 bg-gray-700 text-white rounded hover:bg-gray-600 text-sm">
            Rot X
          </button>
          <button onClick={() => handleRotate('y')} className="px-3 py-1.5 bg-blue-600 text-white rounded hover:bg-blue-700 text-sm">
            Rot Y
          </button>
          <button onClick={() => handleRotate('z')} className="px-3 py-1.5 bg-gray-700 text-white rounded hover:bg-gray-600 text-sm">
            Rot Z
          </button>
        </div>
      </div>

      <div className="border border-app rounded-lg overflow-hidden bg-gray-900 relative">
        <canvas ref={canvasRef} className="w-full h-[500px] block" />
        {loading && (
          <div className="absolute inset-0 flex items-center justify-center bg-black/50 text-white">
            Loading...
          </div>
        )}
        {error && (
          <div className="absolute inset-0 flex items-center justify-center bg-black/80 text-red-400 p-4 text-center">
            {error}
          </div>
        )}
      </div>

      <div className="text-xs muted flex justify-between px-1">
        <span>Left Click: Rotate | Right Click: Pan | Scroll: Zoom</span>
      </div>
    </div>
  );
}