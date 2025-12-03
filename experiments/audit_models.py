import os, joblib, json
from catboost import CatBoostClassifier

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models'))



def sniff_static(path):
    mdl = joblib.load(path)
    est = mdl[-1] if hasattr(mdl, '__getitem__') else mdl
    cls = est.__class__.__name__
    return cls

def sniff_behav(path):
    cb = CatBoostClassifier()
    cb.load_model(path)
    return "CatBoostClassifier"

def main():
    opt = os.path.join(BASE, 'optimized')

    static_model = os.path.join(opt, 'static_xgb_tuned.joblib')
    static_feats  = os.path.join(opt, 'static_xgb_feature_names.joblib')
    static_thr    = os.path.join(opt, 'static_xgb_threshold.json')

    behav_model = os.path.join(opt, 'behav_catboost_tuned.cbm')
    behav_feats  = os.path.join(opt, 'behav_feature_names.json')
    behav_thr    = os.path.join(opt, 'behav_threshold.json')

    print('--- STATIC ---')
    print('model:', static_model, '->', sniff_static(static_model))
    print('feats exist:', os.path.exists(static_feats))
    print('thr:', json.load(open(static_thr)) if os.path.exists(static_thr) else 'MISSING')

    print('\n--- BEHAV ---')
    print('model:', behav_model, '->', sniff_behav(behav_model))
    print('feats exist:', os.path.exists(behav_feats))
    print('thr:', json.load(open(behav_thr)) if os.path.exists(behav_thr) else 'MISSING')

    # Optional baseline RF comparison
    rf = os.path.join(BASE, 'static_rf.joblib')
    if os.path.exists(rf):
        print('\n--- BASELINE RF (STATIC) ---')
        print('model:', rf, '->', sniff_static(rf))

if __name__ == "__main__":
    main()
