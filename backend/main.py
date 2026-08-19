import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from backend.analyzer import K8sAnalyzer

app = FastAPI(title="K8s-Pathfinder API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

@app.get("/api/scan")
def scan_cluster():
    analyzer = K8sAnalyzer()
    graph = analyzer.scan_cluster()
    paths = analyzer.find_attack_paths()
    
    nodes_data = [{"id": n, "data": d} for n, d in graph.nodes(data=True)]
    edges_data = [{"source": u, "target": v, "relation": d.get("relation")} for u, v, d in graph.edges(data=True)]
    
    return {
        "nodes": nodes_data,
        "edges": edges_data,
        "attack_paths": paths
    }

@app.get("/")
def serve_index():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

app.mount("/static", StaticFiles(directory=frontend_dir), name="static")
