# loader.py

import os
import sys
import asyncio
from dotenv import load_dotenv

# Handle PyInstaller frozen executable paths
if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
else:
    base_dir = os.path.dirname(__file__)

# Load environment variables from .env
dotenv_path = os.path.join(base_dir, ".env")
load_dotenv(dotenv_path)

# Import after dotenv (to ensure env vars are available)
from main import create_app, emit_progress, mark_server_ready  # adjust if needed
import uvicorn

# Global app instance
app_instance = None

async def get_app():
    global app_instance
    if app_instance is None:
        app_instance = await create_app()
    return app_instance

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()

    # Use uvicorn factory mode to handle async app creation
    uvicorn.run(
        "loader:get_app",           # module:function
        factory=True,               # tells Uvicorn to await get_app()
        host="0.0.0.0",
        port=8000,
        reload=False,
        loop="asyncio",
        http="httptools",
        log_level="info"
    )
