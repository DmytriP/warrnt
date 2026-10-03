import importlib, sys
for mod in ["fastapi","uvicorn","httpx","pytest","starlette","pydantic","mcp","anyio"]:
    try:
        m = importlib.import_module(mod)
        v = getattr(m, "__version__", "?")
        print(f"OK   {mod} {v}")
    except Exception as e:
        print(f"MISS {mod}: {e}")
print("python", sys.version)
