# Construction Tracker (Vite + React + TypeScript + Node + Python)

This repo now contains:

1) **Frontend**: Vite + React + TypeScript
2) **Backend**: Node.js + TypeScript (Express) + **MongoDB** (Mongoose)
3) **Computation**: Python (Open3D) for scan volume estimation / change detection
4) **Reporting**: Real PDF + XLSX generation (PDFKit + ExcelJS)

## Run locally (dev)

### 1) Start MongoDB

- Local MongoDB: `mongodb://127.0.0.1:27017/construction_tracker`
- Or MongoDB Atlas free tier: set `MONGODB_URI` in `backend/.env`

### 2) Backend

```bash
cd backend
npm i
npm run dev
```

#### Backend env (Atlas / Gemini / deployment)

- Create a `backend/.env` locally (do not commit it) and set:
  - `MONGODB_URI` (MongoDB Atlas recommended)
  - `GEMINI_API_KEY` (optional; enables chatbot + recommendations)
  - `PYTHON_BIN` (optional; Windows often `python`)

See `backend/ENV.md` for details.

### 3) Python dependencies (volume diff)

```bash
cd backend/python
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

> Notes:
> - **E57** files require optional dependency `pye57`.
> - Large scans are down-sampled in Python for runtime stability.

### 4) Frontend

```bash
npm i
npm run dev
```

The frontend proxies `/api` and `/downloads` to the backend (`http://localhost:4000`).

---

# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Babel](https://babeljs.io/) (or [oxc](https://oxc.rs) when used in [rolldown-vite](https://vite.dev/guide/rolldown)) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## React Compiler

The React Compiler is currently not compatible with SWC. See [this issue](https://github.com/vitejs/vite-plugin-react/issues/428) for tracking the progress.

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type-aware lint rules:

```js
export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...

      // Remove tseslint.configs.recommended and replace with this
      tseslint.configs.recommendedTypeChecked,
      // Alternatively, use this for stricter rules
      tseslint.configs.strictTypeChecked,
      // Optionally, add this for stylistic rules
      tseslint.configs.stylisticTypeChecked,

      // Other configs...
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```

You can also install [eslint-plugin-react-x](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-x) and [eslint-plugin-react-dom](https://github.com/Rel1cx/eslint-react/tree/main/packages/plugins/eslint-plugin-react-dom) for React-specific lint rules:

```js
// eslint.config.js
import reactX from 'eslint-plugin-react-x'
import reactDom from 'eslint-plugin-react-dom'

export default defineConfig([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    extends: [
      // Other configs...
      // Enable lint rules for React
      reactX.configs['recommended-typescript'],
      // Enable lint rules for React DOM
      reactDom.configs.recommended,
    ],
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.node.json', './tsconfig.app.json'],
        tsconfigRootDir: import.meta.dirname,
      },
      // other options...
    },
  },
])
```
