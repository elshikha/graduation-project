import json
import sys
import requests
import logging
from pathlib import Path

# ==================================================
# CONFIGURATION
# ==================================================

ALLAM_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.2:3b"

PROMPT_PATH = Path("prompts/analysis_prompt (arabic).txt")
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
    logger.info("تحميل ملف التعليمات (Prompt) باللغة العربية")
    if not PROMPT_PATH.exists():
        logger.error("ملف التعليمات غير موجود")
        raise FileNotFoundError(f"Prompt file not found: {PROMPT_PATH}")

    return PROMPT_PATH.read_text(encoding="utf-8")

# ==================================================
# LOAD ANALYSIS JSON
# ==================================================

def load_analysis_json(json_path: Path):
    logger.info(f"تحميل ملف التحليل: {json_path}")
    if not json_path.exists():
        logger.error("ملف التحليل غير موجود")
        raise FileNotFoundError(f"Analysis JSON not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)

# ==================================================
# GENERATE REPORT USING ALLAM
# ==================================================

def generate_report(prompt: str, analysis_data: dict) -> str:
    logger.info("إرسال البيانات إلى نموذج اللغة العربية (ALLaM)")

    full_prompt = f"""
{prompt}

-------------------------------
بيانات الإدخال (JSON):
{json.dumps(analysis_data, indent=2, ensure_ascii=False)}
"""

    payload = {
        "model": MODEL_NAME,
        "prompt": full_prompt,
        "stream": False
    }

    response = requests.post(ALLAM_URL, json=payload)

    if response.status_code != 200:
        logger.error("خطأ أثناء الاتصال بنموذج اللغة")
        raise RuntimeError(f"LLM API error: {response.text}")

    logger.info("تم توليد التقرير بنجاح")
    return response.json().get("response", "")

# ==================================================
# SAVE REPORT
# ==================================================

def save_report(sample_path: Path, report_text: str):
    REPORTS_DIR.mkdir(exist_ok=True)

    report_name = f"{sample_path.stem}_report_ar.md"
    report_path = REPORTS_DIR / report_name

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    logger.info(f"تم حفظ التقرير: {report_path}")

# ==================================================
# MAIN
# ==================================================

def main():
    if len(sys.argv) != 2:
        logger.error("عدد الوسائط غير صحيح")
        print("\nطريقة الاستخدام:")
        print("python generate_report_ar.py samples/sample_01_high.json\n")
        sys.exit(1)

    sample_path = Path(sys.argv[1])

    try:
        logger.info("===== بدء توليد التقرير العربي =====")

        prompt = load_prompt()
        analysis_data = load_analysis_json(sample_path)

        report = generate_report(prompt, analysis_data)
        save_report(sample_path, report)

        logger.info("===== تم الانتهاء بنجاح =====")

    except Exception as e:
        logger.exception("حدث خطأ أثناء تنفيذ البرنامج")
        sys.exit(1)

# ==================================================
# ENTRY POINT
# ==================================================

if __name__ == "__main__":
    main()