from pathlib import Path
from datetime import datetime
import traceback
import pandas as pd
import io
import re

from fastapi import FastAPI, UploadFile, File, Request, HTTPException, Body
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

from src.behav_model import predict_behav
from src.static_model import predict_static
from src.db.connection import insert_log, fetch_logs
from src.pe_static_extractor import extract_pe_features


app = FastAPI(
    title="Ransomware Detection API",
    description="Uploads a suspicious file, runs ML detection (behavioral + static), logs result.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


# =========================================================
# MODEL FUSION (Hybrid Mode + Soft Explainability)
# =========================================================

FUSION_WEIGHTS = (0.6, 0.4)   
FUSION_THRESHOLD = 0.50       


def risk_band_from_prob(p: float) -> str:
    if p < 0.30:
        return "Safe"
    if p <= 0.70:
        return "Caution"
    return "High Risk"


def combine_model_outputs(df: pd.DataFrame):
    final_reasons = []
    debug_info = {}

    static_prob = None
    behav_prob = None

    # ---- Behavioral Model ----
    try:
        b_probs, b_preds, b_thr, b_reasons = predict_behav(df)
        behav_prob = float(b_probs.mean())
        final_reasons.extend(b_reasons)
        debug_info["behavioral"] = {
            "threshold": b_thr,
            "mean_probability": behav_prob,
        }
    except Exception as e:
        debug_info["behavioral_error"] = str(e)

    # ---- Static Model ----
    try:
        s_probs, s_preds, s_thr, s_reasons = predict_static(df)
        static_prob = float(s_probs.mean())
        final_reasons.extend(s_reasons)
        debug_info["static"] = {
            "threshold": s_thr,
            "mean_probability": static_prob,
        }
    except Exception as e:
        debug_info["static_error"] = str(e)

    # ---- Fusion Logic ----
    if static_prob is not None and behav_prob is not None:
        final_prob = FUSION_WEIGHTS[0] * static_prob + FUSION_WEIGHTS[1] * behav_prob
    elif static_prob is not None:
        final_prob = static_prob
    elif behav_prob is not None:
        final_prob = behav_prob
    else:
        raise RuntimeError("Both models failed.")

    verdict = "Malicious" if final_prob >= FUSION_THRESHOLD else "Safe"
    band = risk_band_from_prob(final_prob)
    debug_info["risk_band"] = band

    # ---- Soft-Friendly Explanation ----
    seen = set()
    reasons = []
    for r in final_reasons:
        if r not in seen:
            seen.add(r)
            reasons.append(r)
        if len(reasons) == 3:
            break

    debug_info["reasons"] = reasons

    return final_prob, verdict, debug_info


# =========================================================
# ROUTES
# =========================================================

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "status": "Protected",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    )


@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
 
    try:
        raw_bytes = await file.read()

        # ---------- Parse uploaded file safely ----------
        try:
            # Try CSV first
            df = pd.read_csv(io.BytesIO(raw_bytes))
        except pd.errors.EmptyDataError:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty. Please upload a CSV with extracted features.",
            )
        except Exception:
            # Try Excel as fallback
            try:
                df = pd.read_excel(io.BytesIO(raw_bytes))
            except Exception:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid file format. Please upload a CSV or XLSX file containing the required features.",
                )

        # ---------- Run fusion detection ----------
        try:
            final_prob, verdict, debug_info = combine_model_outputs(df)
        except KeyError as e:
            # Missing required feature column
            raise HTTPException(
                status_code=400,
                detail=f"Missing required column in CSV: {e}. "
                       "Ensure your file includes all expected feature columns.",
            )
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid value in CSV: {e}",
            )
        except Exception as model_err:
            traceback.print_exc()
            raise HTTPException(
                status_code=500,
                detail=f"Model inference failed: {model_err}",
            )

        # ---------- Store result in DB (non-critical) ----------
        try:
            insert_log(
                filename=file.filename,
                verdict=verdict,
                probability=final_prob,
            )
        except Exception as log_err:
            print("⚠ DB insert failed:", log_err)

        # ---------- Response to UI ----------
        return {
            "status": "ok",
            "filename": file.filename,
            "verdict": verdict,
            "final_prob": final_prob,
            "decision_thresholds": {"safe_max": 0.30, "caution_max": 0.70},
            "risk_band": debug_info.get("risk_band"),
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "debug": debug_info,
            "reasons": debug_info.get("reasons", []),
        }

    except HTTPException:
        # Re-throw clean FastAPI errors
        raise
    except Exception as outer_err:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {outer_err}",
        )

@app.post("/scan_exe")
async def scan_exe(file: UploadFile = File(...)):
    try:
        filename = file.filename or "(unnamed)"
        raw_bytes = await file.read()

        if not filename.lower().endswith((".exe", ".dll")):
            raise HTTPException(
                status_code=400,
                detail="Please upload a Windows PE executable (.exe or .dll).",
            )

        # ---- Extract PE features into a single-row DataFrame ----
        try:
            df = extract_pe_features(raw_bytes)
        except ValueError as ve:
            # Not a valid PE file
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as e:
            traceback.print_exc()
            raise HTTPException(
                status_code=500,
                detail=f"Failed to extract PE features: {e}",
            )

        # ---- Static model prediction (no behavioural here) ----
        try:
            s_probs, s_preds, s_thr, s_reasons = predict_static(df)
            static_prob = float(s_probs.mean())
        except Exception as e:
            traceback.print_exc()
            raise HTTPException(
                status_code=500,
                detail=f"Static model inference failed: {e}",
            )

        final_prob = static_prob
        verdict = "Malicious" if final_prob >= FUSION_THRESHOLD else "Safe"
        band = risk_band_from_prob(final_prob)

        debug = {
            "static": {
                "threshold": s_thr,
                "mean_probability": static_prob,
            },
            "behavioral_error": "No behavioural data for EXE scan (static-only).",
            "risk_band": band,
            "reasons": s_reasons,
        }

        # ---- Log to DB (optional but nice) ----
        try:
            insert_log(
                filename=filename,
                verdict=verdict,
                probability=final_prob,
            )
        except Exception as log_err:
            print("⚠ DB insert failed:", log_err)

        return {
            "status": "ok",
            "filename": filename,
            "verdict": verdict,
            "final_prob": final_prob,
            "decision_thresholds": {"safe_max": 0.30, "caution_max": 0.70},
            "risk_band": band,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "debug": debug,
            "reasons": s_reasons,
            "source_type": "exe_static",
        }

    except HTTPException:
        raise
    except Exception as outer_err:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error (exe scan): {outer_err}",
        )
    
@app.post("/scan_behavioral")
async def scan_behavioral(file: UploadFile = File(...)):
    """
    Behavioural-only scan endpoint.

    Expects a CSV with aggregated Sysmon features, e.g.:
        - total_events
        - n_proc_create
        - n_file_create
        - n_net_conn
        - ratio_proc_create
        - ratio_file_create
        - ratio_net_conn
    """
    try:
        raw_bytes = await file.read()

        try:
            df = pd.read_csv(io.BytesIO(raw_bytes))
        except pd.errors.EmptyDataError:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty. Please upload a CSV with aggregated behavioural features.",
            )
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid file format. Please upload a CSV file containing aggregated behavioural features.",
            )

        # ---- Behavioural model only ----
        try:
            b_probs, b_preds, b_thr, b_reasons = predict_behav(df)
            behav_prob = float(b_probs.mean())
        except Exception as e:
            traceback.print_exc()
            raise HTTPException(
                status_code=500,
                detail=f"Behavioural model inference failed: {e}",
            )

        band = risk_band_from_prob(behav_prob)
        verdict = "Malicious" if behav_prob >= FUSION_THRESHOLD else "Safe"

        debug = {
            "behavioral": {
                "threshold": b_thr,
                "mean_probability": behav_prob,
            },
            "risk_band": band,
            "reasons": b_reasons,
        }

        # (Optional) log to DB as a behavioural-only scan
        try:
            insert_log(
                filename=file.filename or "behavioural_csv",
                verdict=verdict,
                probability=behav_prob,
            )
        except Exception as log_err:
            print("⚠ DB insert failed:", log_err)

        return {
            "status": "ok",
            "filename": file.filename,
            "verdict": verdict,
            "final_prob": behav_prob,
            "decision_thresholds": {"safe_max": 0.30, "caution_max": 0.70},
            "risk_band": band,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "debug": debug,
            "reasons": b_reasons,
            "source_type": "behavioural_csv",
        }

    except HTTPException:
        raise
    except Exception as outer_err:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error (behavioural scan): {outer_err}",
        )

    
@app.get("/logs")
async def get_logs():
    try:
        return fetch_logs()
    except Exception as e:
        traceback.print_exc()
        return JSONResponse({"error": f"Failed to fetch logs: {e}"}, status_code=500)
    
@app.get("/logs-web")
async def logs_web(request: Request):
    return templates.TemplateResponse("logs.html", {"request": request})



# =========================================================
# PDF REPORT GENERATION (ReportLab + ASCII sanitiser)
# =========================================================

def ascii_safe(text: str) -> str:
    """Replace any non-ASCII characters for PDF safety."""
    if text is None:
        return ""
    return re.sub(r"[^\x00-\x7F]", "?", str(text))


# =========================================================
# PDF REPORT GENERATION (ReportLab + ASCII sanitiser)
# =========================================================

def ascii_safe(text: str) -> str:
    """Replace any non-ASCII characters for PDF safety."""
    if text is None:
        return ""
    return re.sub(r"[^\x00-\x7F]", "?", str(text))


@app.post("/report")
async def generate_report(payload: dict = Body(...)):
    try:
        # ----- Extract from payload -----
        filename = payload.get("filename", "(unknown)")
        verdict = payload.get("verdict", "Unknown")
        final_prob = float(payload.get("final_prob", 0.0) or 0.0)
        risk_band = payload.get("risk_band", "Unknown")
        debug = payload.get("debug", {}) or {}
        reasons = payload.get("reasons", []) or []
        scan_ts = payload.get("timestamp")

        # Decision thresholds
        dt = payload.get("decision_thresholds") or {}
        safe_max = dt.get("safe_max", 0.30)
        caution_max = dt.get("caution_max", 0.70)

        # Model details
        behav = debug.get("behavioral") or {}
        stat = debug.get("static") or {}

        behav_prob = behav.get("mean_probability")
        behav_thr = behav.get("threshold")

        static_prob = stat.get("mean_probability")
        static_thr = stat.get("threshold")

        # ----- Create PDF in memory -----
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        y = height - 50

        # ===== Title =====
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, ascii_safe("WannaCry Ransomware Detection Report"))
        y -= 30

        # ===== Metadata =====
        c.setFont("Helvetica", 10)
        c.drawString(50, y, ascii_safe(f"Generated at: {datetime.now().isoformat(timespec='seconds')}"))
        y -= 15
        if scan_ts:
            c.drawString(50, y, ascii_safe(f"Scan timestamp: {scan_ts}"))
            y -= 15
        c.drawString(50, y, ascii_safe(f"File name: {filename}"))
        y -= 25

        # ===== Scan Summary =====
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Scan Summary")
        y -= 18
        c.setFont("Helvetica", 10)
        c.drawString(60, y, ascii_safe(f"Final verdict: {verdict}"))
        y -= 15
        c.drawString(60, y, ascii_safe(f"Final probability (malicious): {final_prob:.3f}"))
        y -= 15
        c.drawString(60, y, ascii_safe(f"Risk band: {risk_band}"))
        y -= 15
        c.drawString(60, y, ascii_safe(
            f"Decision thresholds → Safe ≤ {safe_max:.2f}, "
            f"Caution ≤ {caution_max:.2f}, High Risk > {caution_max:.2f}"
        ))
        y -= 25

        # Helper for page break
        def ensure_space(current, needed=80):
            nonlocal c, width, height
            if current < needed:
                c.showPage()
                c.setFont("Helvetica", 10)
                return height - 50
            return current

        # ===== Score Breakdown =====
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Score Breakdown")
        y -= 18
        c.setFont("Helvetica", 10)

        if static_prob is not None:
            c.drawString(60, y, ascii_safe(
                f"Static risk score: {static_prob:.3f}"
                + (f"  (threshold: {static_thr:.3f})" if static_thr else "")
            ))
            y -= 15

        if behav_prob is not None:
            c.drawString(60, y, ascii_safe(
                f"Behavioural risk score: {behav_prob:.3f}"
                + (f"  (threshold: {behav_thr:.3f})" if behav_thr else "")
            ))
            y -= 15

        y -= 10
        y = ensure_space(y)

        # ===== Risk Assessment =====
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Risk Assessment Summary")
        y -= 18
        c.setFont("Helvetica", 10)

        if verdict.lower() == "malicious":
            summary = (
                "The file shows strong indicators of ransomware-like behaviour "
                "based on its observed characteristics and risk scores."
            )
        elif risk_band.lower().startswith("caution"):
            summary = (
                "Some characteristics appear unusual and may require closer inspection "
                "before trusting the file fully."
            )
        else:
            summary = (
                "No significant indicators of ransomware were detected in this scan."
            )

        c.drawString(60, y, ascii_safe(summary))
        y -= 30
        y = ensure_space(y)

        # ===== Key Contributing Factors =====
        if reasons:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(50, y, "Key Contributing Factors")
            y -= 18
            c.setFont("Helvetica", 10)
            for r in reasons:
                c.drawString(60, y, ascii_safe(f"- {r}"))
                y -= 14
                y = ensure_space(y)
            y -= 10

        # ===== Recommended Actions =====
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Recommended Actions")
        y -= 18
        c.setFont("Helvetica", 10)

        if verdict.lower() == "malicious":
            actions = [
                "Immediately isolate the host from the network.",
                "Do not execute or open the file again.",
                "Run additional security scans and inspect logs.",
                "Preserve file and system state for investigation.",
            ]
        elif risk_band.lower().startswith("caution"):
            actions = [
                "Avoid executing this file on critical systems.",
                "Scan the file using additional tools.",
                "Monitor the device for unusual behaviour.",
            ]
        else:
            actions = [
                "No malicious indicators detected.",
                "Keep backups and maintain system updates.",
                "Re-scan if the file is modified or moved.",
            ]

        for a in actions:
            c.drawString(60, y, ascii_safe(f"- {a}"))
            y -= 14
            y = ensure_space(y)

        # Finish report
        c.showPage()
        c.save()

        buffer.seek(0)
        headers = {
            "Content-Disposition": f'attachment; filename="report_{filename}.pdf"'
        }
        return StreamingResponse(buffer, media_type="application/pdf", headers=headers)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate report: {e}",
        )
