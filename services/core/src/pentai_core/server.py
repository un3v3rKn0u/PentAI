from __future__ import annotations

import threading

import uvicorn

from pentai_core.config import Settings
from pentai_core.main import create_app


def main() -> None:
    settings = Settings.from_environment()
    app = create_app(settings)
    configuration = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,
        access_log=False,
        server_header=False,
    )
    server = uvicorn.Server(configuration)

    def wait_for_shutdown() -> None:
        app.state.shutdown_requested.wait()
        server.should_exit = True

    threading.Thread(target=wait_for_shutdown, daemon=True).start()
    server.run()


if __name__ == "__main__":
    main()
