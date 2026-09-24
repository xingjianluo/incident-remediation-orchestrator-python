"""根入口：复用 app 包内的 FastAPI 应用，接入既有启动方式。"""
from app.api import create_app

app = create_app()
