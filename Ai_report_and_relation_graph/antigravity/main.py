from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import requests
import json
import os

from behavior_graph_builder import BehaviorGraphBuilder

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Example JSON input (replace later with upload)
SAMPLE_FILE = "sample.json"

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    if not os.path.exists(SAMPLE_FILE):
        return HTMLResponse("sample.json not found", status_code=404)
        
    with open(SAMPLE_FILE, "r") as f:
        analysis_data = json.load(f)

    graph = BehaviorGraphBuilder(analysis_data).build()
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "graph": graph
    })

@app.get("/process/{node_id}")
async def process_details(node_id: str):
    if not os.path.exists(SAMPLE_FILE):
         return JSONResponse({"error": "sample.json not found"}, status_code=404)

    with open(SAMPLE_FILE, "r") as f:
        analysis_data = json.load(f)

    graph = BehaviorGraphBuilder(analysis_data).build()

    node = next((n for n in graph["nodes"] if n["id"] == node_id), None)
    if not node or node["type"] != "process":
        return JSONResponse({"error": "Process not found"})

    # Extract related activity
    related_edges = [e for e in graph["edges"] if e["source"] == node_id]

    facts = {
        "process": node["label"],
        "actions": related_edges
    }

    # Call Ollama
    prompt = f"""
You are a cybersecurity malware analyst.
Explain ONLY this process behavior in clear English.
Do not infer behavior not listed.

Facts:
{json.dumps(facts, indent=2)}
"""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3.2:3b",
                "prompt": prompt,
                "stream": False
            },
            timeout=120
        )
        explanation = response.json().get("response", "")
    except Exception as e:
        explanation = f"Error calling Ollama: {str(e)}"

    return {
        "facts": facts,
        "explanation": explanation
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
