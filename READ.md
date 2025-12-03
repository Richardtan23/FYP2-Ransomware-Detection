#  Ransomware Detection System (Static + Behavioural Analysis)

This repository contains the source code for my Final Year Project 2:

> ** Ransomware Detection System using Machine Learning (Static + Behavioural Analysis)**

The system focuses on detecting **WannaCry ransomware** using a combination of:

- **Static analysis** of PE files (XGBoost model)
- **Behavioural analysis** of Sysmon-based features (LightGBM)
- **Hybrid fusion** to combine both signals into a final verdict

The project is implemented as a **FastAPI web application** with an HTML/JS frontend.

---

## 1. Features

- ✅ Upload static feature CSV (or PE-extracted features) for **static detection**
- ✅ Upload behavioural feature CSV (aggregated Sysmon events) for **behaviour detection**
- ✅ **Hybrid fusion** of static + behavioural probabilities
- ✅ Risk band + explanation (top contributing features)
- ✅ Basic **scan history logging** using a database
- ✅ Simple web UI built with HTML, CSS, and JavaScript
- ✅ Demo CSV files for examiners to test the system without real malware

---

## 2. Technology Stack

- **Backend:** Python, FastAPI
- **Frontend:** HTML, CSS, JavaScript
- **Machine Learning:** XGBoost, LightGBM, scikit-learn
- **Database:** MySQL (or MariaDB) for logging scan history
- **Other:** joblib, pandas, numpy

---

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
