import json
import sys
import requests
import logging
from pathlib import Path

# ==================================================
# CONFIGURATION
# ==================================================

ALLAM_URL = "http://localhost:11434/api/generate"
# Note: Changed from "allam" to "llama3.2:3b" to match your local Ollama models
MODEL_NAME = "llama3.2:3b"

PROMPT_PATH = Path("prompts/analysis_prompt_ar.txt")
REPORTS_DIR = Path("reports")
LOGS_DIR = Path("logs")
LOG_FILE = LOGS_DIR / "app.log"

# ==================================================
# LOGGING SETUP
# ==================================================

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

# ==================================================
# LOAD PROMPT
# ==================================================

def load_prompt():
    logger.info("Loading Arabic analysis prompt...")
    if not PROMPT_PATH.exists():
        raise FileNotFoundError(f"Prompt file not found: {PROMPT_PATH}")
    return PROMPT_PATH.read_text(encoding="utf-8")

# ==================================================
# LOAD ANALYSIS JSON
# ==================================================

def load_analysis_json(json_path: Path):
    logger.info(f"Loading analysis JSON: {json_path}")
    if not json_path.exists():
        raise FileNotFoundError(f"Analysis JSON not found: {json_path}")
    return json.loads(json_path.read_text(encoding="utf-8"))

# ==================================================
# GENERATE REPORT
# ==================================================

def generate_report(prompt: str, analysis_data: dict) -> str:
    logger.info(f"Sending request to {MODEL_NAME} model...")

    full_prompt = f"""
{prompt}

==================================================
بيانات الإدخال المنظمة (JSON):
==================================================

{json.dumps(analysis_data, indent=2, ensure_ascii=False)}

==================================================
ابدأ توليد التقرير الآن مع الالتزام التام بالقواعد أعلاه.
"""

    payload = {
        "model": MODEL_NAME,
        "prompt": full_prompt,
        "stream": False
    }

    response = requests.post(ALLAM_URL, json=payload)

    if response.status_code != 200:
        raise RuntimeError(f"LLM API error: {response.text}")

    result = response.json()
    return result.get("response", "").strip()

# ==================================================
# SAVE REPORT
# ==================================================

def save_report(sample_path: Path, report_text: str):
    REPORTS_DIR.mkdir(exist_ok=True)
    report_name = f"{sample_path.stem}_report_ar.md"
    report_path = REPORTS_DIR / report_name
    report_path.write_text(report_text, encoding="utf-8")
    logger.info(f"Report saved: {report_path}")

# ==================================================
# MAIN
# ==================================================

def main():
    if len(sys.argv) != 2:
        print("\nUsage:")
        print("python generate_report_ar.py samples/sample_01.json\n")
        sys.exit(1)

    sample_path = Path(sys.argv[1])

    try:
        logger.info("===== Arabic Report Generation Started =====")

        prompt = load_prompt()
        analysis_data = load_analysis_json(sample_path)

        report = generate_report(prompt, analysis_data)
        save_report(sample_path, report)

        logger.info("===== Report Generated Successfully =====")

    except Exception as e:
        logger.exception("Fatal error during report generation")
        sys.exit(1)

# ==================================================
# ENTRY POINT
# ==================================================

if __name__ == "__main__":
    main()
