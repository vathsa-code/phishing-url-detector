#  Phishing URL Detector

A Python GUI app that detects phishing or malicious URLs using [VirusTotal](https://www.virustotal.com/) API and suspicious keyword analysis. Built with `Tkinter`, it supports both single and batch URL scanning, progress tracking, and logging to CSV.

---

##  Screenshot
![alt text](image.png)

---

## 🚀 How to Run

### 1. Clone this repository

```bash
git clone https://github.com/vathsa-code/phishing-url-detector.git
cd phishing-url-detector

2. Install dependencies
pip install -r requirements.txt

3. Set up your API key
Create a .env file in the project root with this content:
API_KEY=your_virustotal_api_key_here

🧠 Sign up at VirusTotal to get your free API key.

4. Run the application
python main.py