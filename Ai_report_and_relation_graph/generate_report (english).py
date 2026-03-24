import json
import sys
import requests
import logging
from pathlib import Path

# ===== CONFIG =====
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:3b"

PROMPT_PATH = Path("prompts/analysis_prompt.txt")
REPORTS_DIR = Path("reports")
LOGS_DIR = Path("logs")
LOG_FILE = LOGS_DIR / "app.log"

# ===== LOGGING SETUP =====
LOGS_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


# ===== LOAD PROMPT =====
def load_prompt():
    logger.info("Loading analysis prompt")
    if not PROMPT_PATH.exists():
        logger.error("Prompt file not found")
        raise FileNotFoundError(f"Prompt file not found: {PROMPT_PATH}")
    return PROMPT_PATH.read_text(encoding="utf-8")


# ===== LOAD JSON SAMPLE =====
def load_analysis_json(json_path):
    logger.info(f"Loading analysis JSON: {json_path}")
    if not json_path.exists():
        logger.error("Sample JSON file not found")
        raise FileNotFoundError(f"Sample JSON not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ===== SEND TO OLLAMA =====
def generate_report(prompt, analysis_data):
    logger.info("Sending data to local LLM")

    full_prompt = f"""
{prompt}

--- ANALYSIS INPUT JSON ---
{json.dumps(analysis_data, indent=2)}
"""

    payload = {
        "model": MODEL_NAME,
        "prompt": full_prompt,
        "stream": False
    }

    response = requests.post(OLLAMA_URL, json=payload)

    if response.status_code != 200:
        logger.error("Ollama API error")
        raise RuntimeError(f"Ollama API error: {response.text}")

    logger.info("Report generated successfully")
    return response.json()["response"]


# ===== SAVE REPORT =====
def save_report(sample_path, report_text):
    REPORTS_DIR.mkdir(exist_ok=True)

    report_name = sample_path.stem + "_report.md"
    report_path = REPORTS_DIR / report_name

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    logger.info(f"Report saved: {report_path}")


# ===== MAIN =====
def main():
    if len(sys.argv) != 2:
        logger.error("Invalid arguments")
        print("\nUsage:")
        print("python generate_report.py samples/sample_01_high.json\n")
        sys.exit(1)

    sample_path = Path(sys.argv[1])

    try:
        logger.info("=== Report generation started ===")
        prompt = load_prompt()
        analysis_data = load_analysis_json(sample_path)
        report = generate_report(prompt, analysis_data)
        save_report(sample_path, report)
        logger.info("=== Report generation completed successfully ===")
    except Exception as e:
        logger.exception("Fatal error during report generation")
        sys.exit(1)


if __name__ == "__main__":
    main()