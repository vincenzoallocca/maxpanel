import csv
import ipaddress
import json
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
import uuid

from flask import Flask, jsonify, render_template, request, send_file, send_from_directory
from flask_session import Session
from werkzeug.utils import secure_filename

import config
from minecraft_scanner import batch_minecraft_check

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["SESSION_TYPE"] = "filesystem"
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
Session(app)

for folder in [config.SCAN_DIR, config.CLEAN_DIR, config.UPLOAD_DIR, config.OUTPUT_DIR]:
    os.makedirs(folder, exist_ok=True)

SCAN_JOBS = {}
ALLOWED_EXTENSIONS = {'txt'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    conn = sqlite3.connect(config.HISTORY_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def save_history(scan_id, result_file, export_path, summary):
    db = get_db()
    db.execute(
        "INSERT INTO history (scan_id, result_file, export_path, created, summary) VALUES (?, ?, ?, datetime('now'), ?)",
        (scan_id, result_file, export_path, json.dumps(summary))
    )
    db.commit()
    db.close()

def setup_db():
    db = get_db()
    db.execute(
        "CREATE TABLE IF NOT EXISTS history (scan_id TEXT PRIMARY KEY, result_file TEXT, export_path TEXT, created TEXT, summary TEXT)"
    )
    db.commit()
    db.close()
setup_db()

def rate_limit(ip, limit=2, window=60):
    db = get_db()
    now = int(time.time())
    db.execute("CREATE TABLE IF NOT EXISTS ratelimit (ip TEXT, ts INTEGER)")
    db.execute("DELETE FROM ratelimit WHERE ts < ?", (now - window,))
    db.commit()
    count = db.execute("SELECT COUNT(*) as c FROM ratelimit WHERE ip=?", (ip,)).fetchone()["c"]
    if count >= limit:
        db.close()
        return False
    db.execute("INSERT INTO ratelimit (ip, ts) VALUES (?, ?)", (ip, now))
    db.commit()
    db.close()
    return True

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def start_scan():
    user_ip = request.remote_addr
    if not rate_limit(user_ip, 3, 120):
        return jsonify({"status": "error", "message": "Troppi job da questo IP. Riprovare tra qualche minuto."}), 429

    rate = request.form.get("rate")
    ports = request.form.get("ports")
    ip = request.form.get("ip", "").strip()
    file = request.files.get("file")
    use_checker = request.form.get("checker") == "on"

    if not rate or not ports:
        return jsonify({"status": "error", "message": "Dati mancanti (rate/ports)."}), 400
    try:
        rate_val = int(rate)
        if rate_val < 1 or rate_val > 1000000:
            return jsonify({"status": "error", "message": "Rate non valido (1-1000000)."}), 400
    except ValueError:
        return jsonify({"status": "error", "message": "Rate non è un numero valido."}), 400

    is_file_upload = file and file.filename
    if not ip and not is_file_upload:
        return jsonify({"status": "error", "message": "Inserisci IP o File."}), 400

    scan_id = str(uuid.uuid4())
    scan_filename = f"scan_{scan_id}.txt"
    scan_file_path = os.path.join(config.SCAN_DIR, scan_filename)
    clean_file_path = os.path.join(config.CLEAN_DIR, f"clean_{scan_id}.txt")
    upload_file_path = ""
    scan_input = ""

    if is_file_upload:
        if not allowed_file(file.filename):
            return jsonify({"status": "error", "message": "Formato file non valido."}), 400
        upload_filename = f"upload_{scan_id}.txt"
        upload_file_path = os.path.join(config.UPLOAD_DIR, secure_filename(upload_filename))
        file.save(upload_file_path)
        scan_input = upload_file_path
    elif ip:
        try:
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            return jsonify({"status": "error", "message": "Formato IP/Range non valido."}), 400
        with open(scan_file_path, "w") as f:
            f.write(ip + "\n")
        scan_input = scan_file_path
    else:
        return jsonify({"status": "error", "message": "Errore input IP/file."}), 400

    SCAN_JOBS[scan_id] = {
        "status": "pending",
        "progress": 0,
        "result": "",
        "message": "Inizializzazione...",
        "output_data": None
    }
    thread = threading.Thread(
        target=run_scan_thread,
        args=(scan_id, scan_input, clean_file_path, use_checker, ports, rate)
    )
    thread.daemon = True
    thread.start()
    logger.info(f"Started scan job {scan_id}")
    return jsonify({"status": "ok", "scan_id": scan_id})

def split_file(input_file, num_chunks):
    with open(input_file) as f:
        lines = [line.strip() for line in f if line.strip()]
    chunk_size = max(1, len(lines) // num_chunks)
    files = []
    for i in range(num_chunks):
        part = lines[i*chunk_size:(i+1)*chunk_size]
        if part:
            fname = f"{input_file}_chunk_{i}.txt"
            with open(fname, "w") as pfile:
                pfile.write("\n".join(part))
            files.append(fname)
    return files

def parallel_masscan(ip_files, ports, rate):
    results = []
    jobs = []
    for ipf in ip_files:
        out_file = ipf + ".result"
        cmd = [config.MASSCAN_PATH, f"-p{ports}", "-iL", ipf, "--open-only", "--wait", "0", "--max-rate", str(rate), "-oL", out_file]
        p = subprocess.Popen(cmd)
        jobs.append((p, out_file, ipf))
    for p, out_file, ipf in jobs:
        p.wait()
    for _, out_file, ipf in jobs:
        if os.path.exists(out_file):
            with open(out_file) as f:
                for line in f:
                    match = re.search(r'open \w+ (\d+) ([\d\.]+)', line)
                    if match:
                        port = match.group(1)
                        ip = match.group(2)
                        results.append(f"{ip}:{port}")
            os.remove(out_file)
        os.remove(ipf)
    return results

def run_scan_thread(scan_id, scan_input, clean_file_path, use_checker, ports, rate):
    current_job = SCAN_JOBS[scan_id]
    t_total_start = time.time()
    logger.info(f"[SCAN-{scan_id}] Starting Masscan phase")
    chunk_files = split_file(scan_input, 8)
    clean_ips = parallel_masscan(chunk_files, ports, rate)
    with open(clean_file_path, "w", encoding="utf-8") as f:
        f.write("\n".join(clean_ips))
    current_job["progress"] = 50
    current_job["message"] = f"Masscan completato, {len(clean_ips)} IP trovati, avvio checker..."

    output_items = []
    if use_checker:
        logger.info(f"[SCAN-{scan_id}] Starting Minecraft checker phase")
        results, bench = batch_minecraft_check(clean_ips, current_job)
        for ip_port, result_str in results:
            ip, port = ip_port.split(':')
            info = {"ip": ip, "port": port, "result": result_str}
            output_items.append(info)
        summary = {
            "count": len(results),
            "completed": True,
            "checker_sec": bench["duration"],
            "checker_ips": bench["ips_per_sec"]
        }
        current_job["message"] += f" | Checker: {bench['duration']:.2f}s, {bench['ips_per_sec']:.2f} IP/s"
    else:
        for ip_port in clean_ips:
            ip, port = ip_port.split(':')
            info = {"ip": ip, "port": port, "result": "Masscan open"}
            output_items.append(info)
        summary = {
            "count": len(output_items),
            "completed": True
        }
    output_file_path = os.path.join(config.OUTPUT_DIR, f"output_{scan_id}.json")
    with open(output_file_path, "w", encoding='utf-8') as f:
        json.dump(output_items, f)
    current_job["status"] = "completed"
    current_job["progress"] = 100
    current_job["result"] = f"/output/{os.path.basename(output_file_path)}"
    current_job["message"] = "Scansione completata!"
    current_job["output_data"] = output_items
    save_history(scan_id, output_file_path, output_file_path, summary)

    try:
        if os.path.exists(scan_input): os.remove(scan_input)
        if os.path.exists(clean_file_path): os.remove(clean_file_path)
    except Exception as e:
        logger.warning(f"[SCAN-{scan_id}] Cleanup error: {e}")
    t_total_end = time.time()
    logger.info(f"[SCAN-{scan_id}] Job completed in {t_total_end-t_total_start:.2f}s ({summary['count']} results)")

@app.route("/progress/<scan_id>", methods=["GET"])
def get_progress(scan_id):
    job = SCAN_JOBS.get(scan_id)
    if not job:
        return jsonify({"status": "error", "message": "Job non trovato"}), 404
    return jsonify(job)

@app.route("/output/<filename>", methods=["GET"])
def get_output(filename):
    ext = filename.split('.')[-1]
    full_path = os.path.join(config.OUTPUT_DIR, filename)
    if ext == "json":
        with open(full_path, "r", encoding='utf-8') as f:
            data = json.load(f)
        return jsonify(data)
    return send_from_directory(config.OUTPUT_DIR, filename)

@app.route("/export/<scan_id>/<ftype>", methods=["GET"])
def export_scan(scan_id, ftype):
    db = get_db()
    res = db.execute("SELECT result_file FROM history WHERE scan_id=?", (scan_id,)).fetchone()
    db.close()
    if not res: return "Scan non trovato", 404
    file_path = res["result_file"]
    with open(file_path, "r", encoding='utf-8') as f:
        data = json.load(f)
    if ftype == "csv":
        si = []
        header = ["ip", "port", "result"]
        for row in data:
            si.append([row.get(h, "") for h in header])
        path = os.path.join(config.OUTPUT_DIR, f"export_{scan_id}.csv")
        with open(path, "w", encoding='utf-8', newline="") as fcsv:
            out = csv.writer(fcsv)
            out.writerow(header)
            out.writerows(si)
        return send_file(path, mimetype="text/csv", as_attachment=True)
    elif ftype == "txt":
        path = os.path.join(config.OUTPUT_DIR, f"export_{scan_id}.txt")
        with open(path, "w", encoding='utf-8') as ftxt:
            for row in data:
                ftxt.write(f'{row["ip"]}:{row["port"]}\n')
        return send_file(path, mimetype="text/plain", as_attachment=True)
    elif ftype == "json":
        return jsonify(data)
    else:
        return "Formato non supportato", 400

@app.route("/history", methods=["GET"])
def get_history():
    db = get_db()
    scans = db.execute("SELECT scan_id, created, summary FROM history ORDER BY created DESC LIMIT 6").fetchall()
    db.close()
    output = []
    for scan in scans:
        info = {
            "scan_id": scan["scan_id"],
            "created": scan["created"],
            "summary": json.loads(scan["summary"])
        }
        output.append(info)
    return jsonify(output)

if __name__ == "__main__":
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLASK_PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )
