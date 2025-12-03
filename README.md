# 🚀 Ransomware Detection System (Static + Behavioural Analysis)

This repository contains the full source code for my **Final Year Project 2**:

> **AI-Powered Ransomware Detection System using Machine Learning (Static + Behavioural Analysis)**

The system detects **WannaCry ransomware** using a hybrid ML approach:

- **Static Analysis** – PE file feature classification (XGBoost)  
- **Behavioural Analysis** – Sysmon event aggregation + ML detection (LightGBM)  
- **Hybrid Fusion** – Weighted probability fusion (static + behavioural)

The system runs on **FastAPI** with an HTML/CSS/JS frontend.

---

## ✅ 1. Features

- ✔ Static detection using **XGBoost**
- ✔ Behavioural detection using **LightGBM / CatBoost**
- ✔ Hybrid fusion engine (0.6 static + 0.4 behaviour)
- ✔ Probability score + risk banding
- ✔ Feature explanation (top contributing indicators)
- ✔ MySQL scan-history logging
- ✔ Simple web UI (upload → detect → risk output)
- ✔ Demo CSV samples included for examiners  
  *(No malware required)*

---

## 🧠 2. Technology Stack

### **Backend**
- Python 3.10+
- FastAPI
- Uvicorn
- MySQL / MariaDB

### **Machine Learning**
- XGBoost  
- LightGBM  
- CatBoost  
- scikit-learn  
- pandas / numpy  

### **Frontend**
- HTML  
- CSS  
- JavaScript  

---

## 📁 3. Project Structure

## 3. Project Structure

```text
FYP2/
├── app.py                # Main FastAPI application
├── requirements.txt      # Python dependencies
├── .env.example          # Example environment variables (no secrets)
├── README.md
│
├── static/               # Frontend assets
│   ├── script.js
│   └── style.css
│
├── templates/            # HTML templates
│   ├── index.html
│   └── logs.html
│
├── src/
│   └── db/
│       ├── connection.py # Database connection helper
│       └── schema.sql    # SQL schema for detection_logs table
│
├── models/
│   └── optimized/        # Trained models used in the system
│       ├── static_xgb_tuned.joblib
│       ├── static_xgb_feature_names.joblib
│       ├── static_xgb_threshold.json
│       ├── behav_catboost_tuned.cbm
│       ├── behav_feature_names.json
│       ├── behav_threshold.json
│       └── behav_lgbm.joblib
│
├── notebooks/            # Model training & evaluation (for reference)
│   ├── 01_inspect_datasets.ipynb
│   ├── 02_evaluate_models.ipynb
│   ├── 03_model_optimization.ipynb
│   ├── 04_compare_final_models.ipynb
│   ├── 05_test.ipynb
│   ├── 06_train_behav_lgm.ipynb
│   ├── 07_eval_static.ipynb
│   └── sanity_check.ipynb
│
├── aggregate_behavior_features.py
├── behav_model.py
├── explain_utils.py
├── extract_behavior_features.py
├── pe_static_extractor.py
├── static_model.py
├── utils.py
│
├── demo_static_sample.csv
├── demo_static_malicious.csv
├── demo_behav_sample.csv
├── demo_behav_benign.csv
├── demo_fusion_staticMal_behavMal.csv
└── demo_fusion_staticMal_behavSafe.csv

---

## ▶️ 4. How to Run the System

### **1. Create virtual environment**
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

2. Install dependencies
pip install -r requirements.txt

3. Configure environment variables

Copy:

.env.example → .env


Set:

DB_HOST=localhost
DB_USER=root
DB_PASS=yourpassword
DB_NAME=ransomware_db
DB_PORT=3306

4. Create database schema

Run the SQL in:

src/db/schema.sql

5. Start FastAPI
uvicorn src.app:app --reload

6. Open the web UI
http://127.0.0.1:8000

🧪 5. Demo Test Files
File	Purpose
demo_static_sample.csv	Benign static example
demo_static_malicious.csv	WannaCry-like static signature
demo_behav_sample.csv	Benign behaviour logs
demo_behav_benign.csv	Safe behaviour sample
demo_fusion_staticMal_behavSafe.csv	Mixed-signal fusion test
demo_fusion_staticMal_behavMal.csv	Malicious fusion test
🧾 6. License

This project is for academic use only.

👤 7. Author

Tan Li Cherk
Final Year Project 2
Ransomware Detection System Using Machine Learning
UOW Malaysia
