<!-- Copilot instructions for the FP-Kriptografi-DSS repository -->

# How to help in this repo (concise)

- **Project Type:** Frontend-only React + TypeScript app scaffolded with Vite. The `frontend/` folder contains the app; `backend/` is currently empty.
- **Primary entry:** `frontend/src/main.tsx` → renders `App` from `frontend/src/App.tsx`.
- **Key config:** `frontend/package.json` (scripts: `dev`, `build`, `lint`, `preview`), `frontend/vite.config.ts`, and TypeScript configs (`tsconfig.*.json`).

# Quick commands (run from repo root unless noted)

- cd into the frontend and install dependencies:

- ```powershell

  ```
- cd frontend; npm install
- ```

  ```

- Start dev server:

- ```powershell

  ```
- npm run dev
- ```

  ```

- Build for production (runs `tsc -b` then `vite build`):

- ```powershell

  ```
- npm run build
- ```

  ```

- Preview a production build:

- ```powershell

  ```
- npm run preview
- ```

  ```

- Run linter:

- ```powershell

  ```
- npm run lint
- ```

  ```

# What to look for when making changes

- The app uses React 19 + Vite plugin `@vitejs/plugin-react`. Keep imports and component filenames as `.tsx`.
- Static/public files are referenced using Vite semantics (examples: `/vite.svg` used in `App.tsx`).
- `frontend/src` is the primary implementation area. Files present but empty (likely work-in-progress): `frontend/src/Login.tsx` and `frontend/src/Upload.tsx` — implement features there and follow existing component style from `App.tsx`.
- The `build` script runs `tsc -b` first. If you change TypeScript project references or add packages, ensure the TypeScript build still succeeds before publishing.

# Integration & assumptions

- There is no backend implemented yet (`backend/` is empty). Do not add code that assumes an API exists unless you also create and document the backend API and its run steps. If you add API calls, clearly document the expected endpoints and mock behavior in the frontend README.
- No test runner is present. Avoid adding tests that require a full CI setup unless requested.

# Code style & PR guidance

- Keep changes minimal and focused. Run `npm run lint` and `npm run build` locally in `frontend/` before opening a PR.
- When adding new dependencies, update `frontend/package.json` and ensure `npm run build` still passes.

# Helpful file references

- `frontend/package.json` — scripts and dependencies.
- `frontend/vite.config.ts` — Vite configuration and plugins.
- `frontend/src/main.tsx`, `frontend/src/App.tsx` — app entry and example component.
- `frontend/README.md` — notes about the Vite + React template.

# If unsure

- Ask the repo owner whether a backend is planned and which API contract to follow.
- If you need to scaffold new infra (API, DB), propose it in the PR description and keep frontend changes behind feature flags or mocks.

-- End of guidance --
