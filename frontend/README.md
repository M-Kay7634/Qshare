# QShare dashboard UI

This is a frontend-only dashboard prototype for the QShare research project.

## Install
1. Copy `src/App.jsx`, `src/App.css`, and `src/index.css` into your existing `frontend/src/` folder.
2. Keep your existing `src/main.jsx` and `package.json`.
3. From the `frontend` folder run:
   ```powershell
   npm run dev
   ```

## Current behavior
- Responsive dashboard layout and sidebar navigation
- Search filters the demo file list
- Upload button selects local files and adds their metadata to the demo list
- Clearly labelled prototype/demo status

## Important security note
This is only a UI prototype. Selecting a file does not encrypt or upload it. The sample file list and security status are demo data. Do not use it to store real confidential files. Backend APIs and browser-side cryptography must be integrated and tested before making security claims.
