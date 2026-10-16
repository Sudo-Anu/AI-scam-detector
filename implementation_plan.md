# Background Execution and Auto-Shutdown Implementation

The user wants the application to run completely in the background without any visible terminal windows, and automatically close all background processes (backend and frontend) when the browser tab is closed.

## Proposed Changes

We will introduce a "Heartbeat" mechanism combined with a hidden Python launcher.

### 1. The Heartbeat API (`backend/api/endpoints.py`)
- Add a new `POST /api/heartbeat` endpoint.
- Start a background daemon thread when the FastAPI server boots.
- This thread will monitor the time since the last heartbeat. If no heartbeat is received for 10 seconds (after the first one is established), the backend will cleanly self-terminate using `os._exit(0)`.

### 2. The Frontend Ping (`frontend/src/App.jsx`)
- Add a React `useEffect` hook to ping the `/api/heartbeat` endpoint every 3 seconds.
- When the user closes the browser tab, the pinging will stop naturally, triggering the backend's self-termination.

### 3. The Hidden Launcher (`launcher.py`)
- Create a new `launcher.py` script.
- This script will launch both `uvicorn` (backend) and `npm run dev` (frontend) using `subprocess.Popen` with the `CREATE_NO_WINDOW` flag, ensuring no terminals appear on the screen.
- It will open the user's browser automatically.
- It will wait for the backend process to exit. Once the backend exits (due to the heartbeat timeout), the launcher will forcefully and cleanly kill the frontend `npm`/`node` process tree, and then exit itself.

### 4. Setup Script Update (`start.bat`)
- Modify `start.bat` to display the initial 6 setup steps.
- Instead of launching visible terminal windows at the end, it will simply run `pythonw launcher.py` and exit, leaving zero terminals on the screen!

## User Review Required
> [!IMPORTANT]
> The backend server and frontend server will now run completely hidden from your taskbar. They will rely **entirely** on the browser tab remaining open to stay alive. If you close the tab, everything shuts down automatically. Is this the exact behavior you are looking for?
