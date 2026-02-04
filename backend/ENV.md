## Backend Environment Variables

Set these in your shell, your hosting provider (Vercel/Render/Fly), or a local `backend/.env` file.

- **MONGODB_URI**: MongoDB Atlas connection string
  - Example: `mongodb+srv://USER:PASSWORD@CLUSTER.mongodb.net/construction_tracker?retryWrites=true&w=majority`
- **GEMINI_API_KEY**: (optional) enables `/api/chat` and `/api/recommendations`
- **PYTHON_BIN**: (optional) python executable (Windows often `python`)
- **PORT**: (optional) backend port (default 4000)

Notes:
- In production, don’t commit `.env` files.
- MongoDB Atlas is the recommended DB for deployment.
