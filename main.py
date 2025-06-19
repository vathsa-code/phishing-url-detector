import os
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("API_KEY")

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import requests
import base64
import time
import csv
from datetime import datetime

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "bank", "update", "signin", "paypal", "confirm"]

# VirusTotal and analysis functions remain unchanged
def submit_url_to_virustotal(url):
    headers = {"x-apikey": API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
    data = f"url={url}"
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        return url, result["data"]["id"]
    else:
        print("Error submitting URL:", response.text)
        return None, None

def retrieve_scan_result(original_url):
    headers = {"x-apikey": API_KEY}
    encoded_url = base64.urlsafe_b64encode(original_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    for _ in range(20):
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            stats = result["data"]["attributes"]["last_analysis_stats"]
            return stats
        time.sleep(1)
    print("Timed out waiting for scan result.")
    return None

def check_heuristics(url):
    return [f"suspicious keyword: '{word}'" for word in SUSPICIOUS_KEYWORDS if word in url.lower()]

def analyze_url_gui(url):
    url, _ = submit_url_to_virustotal(url)
    if not url:
        return "ERROR", 0, 0, 0, "Submission failed"
    stats = retrieve_scan_result(url)
    if not stats:
        return "ERROR", 0, 0, 0, "Scan timeout or error"
    harmless = stats.get("harmless", 0)
    suspicious = stats.get("suspicious", 0)
    malicious = stats.get("malicious", 0)
    if malicious > 0:
        verdict, reason = "PHISHING", "Flagged as malicious by antivirus engines"
    elif suspicious > 0:
        verdict, reason = "SUSPICIOUS", "Flagged as suspicious by antivirus engines"
    else:
        reasons = check_heuristics(url)
        verdict = "SUSPICIOUS" if reasons else "SAFE"
        reason = "; ".join(reasons) if reasons else "No threats detected"
    return verdict, harmless, suspicious, malicious, reason

def log_result(url, verdict, harmless, suspicious, malicious, reason):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("result_log.csv", mode="a", newline='', encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "URL", "Verdict", "Harmless", "Suspicious", "Malicious", "Reason"])
        writer.writerow([timestamp, url, verdict, harmless, suspicious, malicious, reason])

# GUI functionality
def scan_single():
    url = entry.get().strip()
    if not url:
        messagebox.showwarning("Input Required", "Please enter a URL.")
        return
    output.insert(tk.END, f"\n🔍 Scanning: {url}")
    verdict, harmless, suspicious, malicious, reason = analyze_url_gui(url)
    result_text = f"\nVerdict: {verdict}\nHarmless: {harmless}, Suspicious: {suspicious}, Malicious: {malicious}\nReason: {reason}\n"
    output.insert(tk.END, result_text)
    output.see(tk.END)
    log_result(url, verdict, harmless, suspicious, malicious, reason)

def batch_check():
    file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv")])
    if not file_path:
        return
    try:
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            urls = [row[0].strip() for row in csv.reader(csvfile) if row]
        total = len(urls)
        if total == 0:
            messagebox.showinfo("Batch Check", "CSV is empty.")
            return
        progress["value"] = 0
        progress["maximum"] = total
        percent_label.config(text="0%")
        for idx, url in enumerate(urls, start=1):
            output.insert(tk.END, f"\n📄 Checking {idx}/{total}: {url}")
            output.update_idletasks()
            verdict, harmless, suspicious, malicious, reason = analyze_url_gui(url)
            log_result(url, verdict, harmless, suspicious, malicious, reason)
            result_line = f"Verdict: {verdict} | Harmless: {harmless}, Suspicious: {suspicious}, Malicious: {malicious} | Reason: {reason}"
            output.insert(tk.END, f"\n{result_line}\n")
            output.see(tk.END)
            progress["value"] = idx
            percent_label.config(text=f"{int((idx / total) * 100)}%")
            root.update_idletasks()
            time.sleep(1)
        messagebox.showinfo("Batch Complete", f"Scanned {total} URLs successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to process file:\n{str(e)}")

# 🎨 Styled GUI Setup
root = tk.Tk()
root.title("🔐 Phishing URL Detector")
root.geometry("760x650")
root.configure(bg="#f1f4f8")

title = tk.Label(root, text="Phishing URL Detector", font=("Helvetica", 20, "bold"), bg="#f1f4f8", fg="#2c3e50")
title.pack(pady=10)

frame = tk.Frame(root, bg="#f1f4f8")
frame.pack(pady=5)

tk.Label(frame, text="Enter URL:", font=("Helvetica", 12), bg="#f1f4f8").grid(row=0, column=0, padx=5)
entry = tk.Entry(frame, width=60, font=("Consolas", 11))
entry.grid(row=0, column=1, padx=5)

button_frame = tk.Frame(root, bg="#f1f4f8")
button_frame.pack(pady=10)

tk.Button(button_frame, text="🔎 Scan URL", command=scan_single, bg="#3498db", fg="white", font=("Helvetica", 11), padx=10, pady=5).grid(row=0, column=0, padx=10)
tk.Button(button_frame, text="📂 Batch Check (CSV)", command=batch_check, bg="#2ecc71", fg="white", font=("Helvetica", 11), padx=10, pady=5).grid(row=0, column=1, padx=10)

progress = ttk.Progressbar(root, orient="horizontal", length=500, mode="determinate")
progress.pack(pady=(15, 2))
percent_label = tk.Label(root, text="0%", font=("Helvetica", 10), bg="#f1f4f8")
percent_label.pack()

output = tk.Text(root, height=20, width=95, wrap="word", bg="#ffffff", font=("Courier", 10), fg="#2d3436", bd=2, relief="solid")
output.pack(pady=10, padx=10)

root.mainloop()
