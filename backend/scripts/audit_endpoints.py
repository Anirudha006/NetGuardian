import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.main import app
from fastapi.routing import APIRoute

def get_all_routes(app):
    routes = []
    for r in app.routes:
        if isinstance(r, APIRoute):
            routes.append(r)
        elif hasattr(r, "original_router"):
            routes.extend(r.original_router.routes)
        elif hasattr(r, "routes"):
            routes.extend(r.routes)
    return routes

def inspect_routes():
    all_routes = get_all_routes(app)
    rows = []
    for r in all_routes:
        if not isinstance(r, APIRoute):
            continue
        methods = sorted(list(r.methods - {"HEAD"}))
        methods_str = ",".join(methods)
        path = r.path
        
        import inspect
        sig = inspect.signature(r.endpoint)
        dep_names = []
        for param in sig.parameters.values():
            if hasattr(param.default, "dependency"):
                dep_fn = param.default.dependency
                dep_names.append(dep_fn.__name__ if hasattr(dep_fn, "__name__") else str(dep_fn))
        
        for d in r.dependencies:
            if hasattr(d, "dependency"):
                dep_fn = d.dependency
                dep_names.append(dep_fn.__name__ if hasattr(dep_fn, "__name__") else str(dep_fn))
        
        rows.append((methods_str, path, dep_names, r.name))
        
    print(f"Total endpoints found: {len(rows)}")
    for m, p, d, name in sorted(rows, key=lambda x: (x[1], x[0])):
        print(f"{m:<8} {p:<45} deps: {d}")

if __name__ == "__main__":
    inspect_routes()
