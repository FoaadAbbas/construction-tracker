🏗️ Construction Tracker
3D Point-Cloud Volume Change Monitoring System
Visit Website: https://construction-tracker-teal.vercel.app/ Username: GeneralU Password: 123456

📌 Overview
Construction Tracker is a full-stack web application designed to monitor construction site progress using 3D point-cloud scans.

The system compares two scans:

T1 – Baseline scan
T2 – Comparison scan
It calculates volumetric changes using a voxel-based algorithm and visualizes the results in an interactive 3D viewer directly in the browser.

This project demonstrates advanced backend engineering, Python integration, real-time communication, and cloud deployment.

🚀 Key Features
Upload LAZ / E57 point-cloud scans
Automatic voxel-based volume estimation
Volume change calculation (m³)
Interactive 3D visualization (orbit, zoom, pan)
Real-time processing updates via WebSockets
Cloud storage using MongoDB Atlas
🏗️ System Architecture
Frontend (React + TypeScript + Vite) ↓ Node.js Backend (Express) ↓ Python Volume Engine (Open3D) ↓ MongoDB Atlas

🛠️ Tech Stack
Frontend
React
TypeScript
Vite
Tailwind CSS
Three.js
Backend
Node.js
Express
WebSockets
Multer
Mongoose
Python Engine
Open3D
laspy
pye57
NumPy
Database
MongoDB Atlas
Deployment
Frontend: Vercel
Backend: Render
⚙️ How It Works
User uploads two point-cloud scans (T1 and T2).

Backend temporarily stores the files.

Node.js spawns a Python subprocess:

python volume_engine.py --t1 scan1.laz --t2 scan2.laz --voxel 0.05

Python:

Loads the scans
Converts them into voxel grids
Calculates individual volumes
Computes volume difference
Returns JSON output
Backend sends results to frontend.

Data is saved to MongoDB.

The 3D viewer renders both scans.

🧠 Volume Estimation Formula
Volume = (# of occupied voxels) × (voxel_size³)

This provides a fast and scalable approximation of volumetric changes between scans.

🔐 Environment Variables
Backend (.env)
MONGO_URI=your_mongodb_connection_string
PORT=5000
PYTHON_PATH=python

Frontend (.env)
VITE_API_URL=http://localhost:5000

🚀 Run Locally
Clone the Repository
git clone
cd construction-tracker

Install Frontend
npm install
npm run dev

Install Backend
cd backend npm install

Install Python Dependencies
cd backend/python pip install open3d laspy pye57 numpy

Start Backend
npm run dev

📊 Use Cases
Construction progress monitoring
Earthwork volume estimation
Excavation tracking
Digital twin validation
Civil engineering analysis
🎓 Academic & Engineering Value
This project showcases:

Full-stack system design
Backend–Python integration
3D spatial data processing
Real-time architecture
Cloud database integration
Production deployment
👨‍💻 Authors
Michael Billan & Foad Abbas Software Engineering Students Backend & Systems-Oriented Engineers

License
All rights reserved © Braude College of Engineering, Software Engineering Department, Michael Billan.
