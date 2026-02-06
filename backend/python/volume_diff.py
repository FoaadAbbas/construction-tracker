#!/usr/bin/env python3
import argparse
import json
import os
import sys
import numpy as np
from typing import Tuple


def _load_point_cloud(path: str):
    if not path or not isinstance(path, str):
        raise RuntimeError(f"Invalid file path value: {path!r}")

    if not os.path.exists(path):
        raise RuntimeError(f"File not found: {path}")

    if os.path.isdir(path):
        raise RuntimeError(f"Expected a file path but got a directory: {path}")

    ext = os.path.splitext(path)[1].lower()

    # Normal, extension-based handling (fast path)
    if ext == ".ply":
        import open3d as o3d
        pcd = o3d.io.read_point_cloud(path)
        return pcd

    if ext in (".las", ".laz"):
        import numpy as np
        import laspy
        import open3d as o3d
        las = laspy.read(path)
        pts = np.vstack((las.x, las.y, las.z)).T.astype("float64")
        pcd = o3d.geometry.PointCloud()
        pcd.points = o3d.utility.Vector3dVector(pts)
        return pcd

    if ext == ".e57":
        import numpy as np
        import open3d as o3d
        try:
            import pye57
        except Exception as e:
            raise RuntimeError(
                "Missing dependency 'pye57' for .e57 files. Install: pip install pye57"
            ) from e

        e57 = pye57.E57(path)
        if e57.scan_count == 0:
            raise RuntimeError("E57 file contains no scans")
        data = e57.read_scan(0, intensity=False, colors=False)
        pts = np.vstack(
            (data["cartesianX"], data["cartesianY"], data["cartesianZ"])
        ).T.astype("float64")
        pcd = o3d.geometry.PointCloud()
        pcd.points = o3d.utility.Vector3dVector(pts)
        return pcd

    # Fallback: extension missing or unexpected -> try to detect by attempting readers.
    # This directly addresses your current failure (ext == "") when backend stores files without suffix.
    # Order: LAS -> E57 -> Open3D generic
    # If all fail, raise a clear error.
    try:
        import numpy as np
        import laspy
        import open3d as o3d

        try:
            las = laspy.read(path)  # works even if extension is missing
            pts = np.vstack((las.x, las.y, las.z)).T.astype("float64")
            pcd = o3d.geometry.PointCloud()
            pcd.points = o3d.utility.Vector3dVector(pts)
            return pcd
        except Exception:
            pass

        try:
            import pye57  # optional
            e57 = pye57.E57(path)
            if e57.scan_count > 0:
                data = e57.read_scan(0, intensity=False, colors=False)
                pts = np.vstack(
                    (data["cartesianX"], data["cartesianY"], data["cartesianZ"])
                ).T.astype("float64")
                pcd = o3d.geometry.PointCloud()
                pcd.points = o3d.utility.Vector3dVector(pts)
                return pcd
        except Exception:
            pass

        try:
            pcd = o3d.io.read_point_cloud(path)
            # If Open3D returns an empty pcd, treat as failure
            if len(pcd.points) > 0:
                return pcd
        except Exception:
            pass

    except Exception:
        # If imports fail (rare), fall through to the final error
        pass

    raise RuntimeError(
        f"Unsupported extension '{ext}'. Supported: .ply, .las/.laz, .e57. "
        f"Path received by job: {path!r}. "
        f"If ext is empty, your backend likely saved the upload without the original suffix."
    )


def _estimate_volume_voxels(pcd, voxel_size: float, max_points: int) -> Tuple[float, int]:
    import numpy as np
    import open3d as o3d

    pts = np.asarray(pcd.points)
    if pts.size == 0:
        return 0.0, 0

    if max_points > 0 and len(pts) > max_points:
        idx = np.random.choice(len(pts), size=max_points, replace=False)
        pcd = o3d.geometry.PointCloud()
        pcd.points = o3d.utility.Vector3dVector(pts[idx])

    vg = o3d.geometry.VoxelGrid.create_from_point_cloud(pcd, voxel_size=voxel_size)
    voxels = vg.get_voxels()
    count = len(voxels)
    volume = count * (voxel_size ** 3)
    return float(volume), int(count)


def extract_points(path: str, max_points: int = 100000):
    """Extract and downsample points from a point cloud file for visualization."""
    ext = os.path.splitext(path)[1].lower()
    
    try:
        if ext in (".las", ".laz"):
            # First check if this might be a well log LAS file (not LiDAR)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1000)  # Read first 1000 characters
                    if content.startswith('#') and ('~Version Information' in content or '~Well Information' in content):
                        raise RuntimeError(f"File appears to be a well log LAS file, not a LiDAR point cloud LAS file. This application expects LiDAR LAS/LAZ format for 3D point cloud data.")
            except UnicodeDecodeError:
                # If we can't read as text, it's probably a binary file, so proceed with laspy
                pass
            
            try:
                import laspy
                
                points_list = []
                colors_list = []
                
                # Use chunked reading to handle large files without OOM
                with laspy.open(path) as fh:
                    total_points = fh.header.point_count
                    
                    # If small enough, read all (faster)
                    if total_points <= max_points:
                        las = fh.read()
                        pts = np.vstack((las.x, las.y, las.z)).T.astype("float64")
                        points_list.append(pts)
                        
                        if hasattr(las, 'red') and hasattr(las, 'green') and hasattr(las, 'blue'):
                            try:
                                r = np.array(las.red, dtype=np.float32) / 65535.0
                                g = np.array(las.green, dtype=np.float32) / 65535.0
                                b = np.array(las.blue, dtype=np.float32) / 65535.0
                                colors_list.append(np.vstack((r, g, b)).T)
                            except:
                                pass
                    else:
                        # Large file: Read in chunks and sample
                        # Probability to keep a point
                        prob = max_points / total_points
                        # Chunk size of 1M points
                        chunk_size = 1_000_000
                        
                        for chunk in fh.chunk_iterator(chunk_size):
                            # Simple random mask selection is fast
                            mask = np.random.rand(len(chunk)) < prob
                            
                            if np.sum(mask) == 0:
                                continue

                            sub_x = chunk.x[mask]
                            sub_y = chunk.y[mask]
                            sub_z = chunk.z[mask]
                            points_list.append(np.vstack((sub_x, sub_y, sub_z)).T.astype("float64"))
                            
                            if hasattr(chunk, 'red') and hasattr(chunk, 'green') and hasattr(chunk, 'blue'):
                                try:
                                    r = np.array(chunk.red[mask], dtype=np.float32) / 65535.0
                                    g = np.array(chunk.green[mask], dtype=np.float32) / 65535.0
                                    b = np.array(chunk.blue[mask], dtype=np.float32) / 65535.0
                                    colors_list.append(np.vstack((r, g, b)).T)
                                except:
                                    pass
                                    
                if not points_list:
                    raise RuntimeError("LAS file contains no points (or sampling failed)")
                    
                points = np.vstack(points_list)
                colors = np.vstack(colors_list) if colors_list else None
                
                # If we still ended up with too many (due to probability), trim
                if len(points) > max_points:
                    idx = np.random.choice(len(points), max_points, replace=False)
                    points = points[idx]
                    if colors is not None:
                        colors = colors[idx]
                        
            except Exception as e:
                error_msg = str(e)
                # Re-raise with more context
                raise RuntimeError(f"Failed to read LiDAR LAS file {os.path.basename(path)}: {error_msg}")
        else:
            # For other formats, try open3d
            try:
                import open3d as o3d
                pcd = _load_point_cloud(path)
                points = np.asarray(pcd.points)
                colors = np.asarray(pcd.colors) if len(pcd.colors) > 0 else None
            except ImportError:
                raise RuntimeError("Open3D not available and unsupported file format")
    except Exception as e:
        # Re-raise the exception instead of generating sample points
        raise RuntimeError(f"Failed to read point cloud file {path}: {e}")
    
    # Downsample if too many points
    if len(points) > max_points:
        # Simple random downsampling
        indices = np.random.choice(len(points), max_points, replace=False)
        points = points[indices]
        if colors is not None:
            colors = colors[indices]
    
    # Prepare result
    result = {"points": points.tolist()}
    if colors is not None:
        result["colors"] = colors.tolist()
    
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--t1", required=False)
    ap.add_argument("--t2", required=False)
    ap.add_argument("--extract", required=False)  # New mode for single file extraction
    ap.add_argument("--voxel", type=float, default=0.05)  # 5cm default
    ap.add_argument("--max_points", type=int, default=2_000_000)
    ap.add_argument("--max_extract_points", type=int, default=300_000)  # For extraction mode
    args = ap.parse_args()

    try:
        if args.extract:
            # Single file extraction mode
            result = extract_points(args.extract, args.max_extract_points)
            print(json.dumps(result))
            return 0
        elif args.t1 and args.t2:
            # Volume comparison mode
            pcd1 = _load_point_cloud(args.t1)
            pcd2 = _load_point_cloud(args.t2)
            v1, c1 = _estimate_volume_voxels(pcd1, args.voxel, args.max_points)
            v2, c2 = _estimate_volume_voxels(pcd2, args.voxel, args.max_points)
            out = {
                "volumeT1M3": v1,
                "volumeT2M3": v2,
                "volumeChangeM3": v2 - v1,
                "voxelSizeM": args.voxel,
                "voxelCountT1": c1,
                "voxelCountT2": c2,
            }
            print(json.dumps(out))
            return 0
        else:
            raise RuntimeError("Must specify either --extract for single file or --t1 and --t2 for comparison")
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
