"""Disposable loopback server shared by integration tests and the local CLI."""

import asyncio
import socket
from contextlib import asynccontextmanager

import uvicorn

from app.lab.application import create_lab_app


@asynccontextmanager
async def local_lab():
    app = create_lab_app()
    state = app.state.lab
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    base = f"http://127.0.0.1:{sock.getsockname()[1]}"
    state.receiver_url = base
    server = uvicorn.Server(
        uvicorn.Config(
            app, host="127.0.0.1", log_level="critical", access_log=False, lifespan="off", ws="none"
        )
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(3):
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("Local fixture failed to start")
                await asyncio.sleep(0.01)
        yield base, state
    finally:
        server.should_exit = True
        try:
            await asyncio.wait_for(task, timeout=3)
        finally:
            sock.close()
            state.close()
