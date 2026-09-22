"""服务入口：启动 FastAPI 应用。"""

from app.api import create_app

app = create_app()


@app.get("/")
def read_root() -> dict:
    return {"service": "threat-ioc-aggregator", "status": "ok"}
