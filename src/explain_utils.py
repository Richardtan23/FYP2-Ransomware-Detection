
from typing import List, Tuple

def friendly_explanations(top_features: List[Tuple[str, float]]) -> list[str]:
    """
    top_features: e.g. [("entropy_mean", 0.41), ("imports_CryptEncrypt", 0.33), ...]
    returns up to 3 short, non-technical reasons.
    """
    msgs = []
    for feat, _ in top_features:
        f = feat.lower()
        if "entropy" in f:
            msgs.append("The file looks heavily scrambled, a common way malware hides itself.")
        elif "import" in f or "crypt" in f or "virtualalloc" in f:
            msgs.append("It appears to contain code related to encrypting or changing files.")
        elif "section" in f or "numberofsections" in f:
            msgs.append("Its internal structure looks unusual compared to normal programs.")
        elif "bitcoin" in f or "btc" in f:
            msgs.append("It has patterns related to cryptocurrency usage.")
        elif "write" in f or "bulk" in f or "encrypt" in f:
            msgs.append("It shows patterns similar to fast file changes seen in ransomware.")
    # keep order, dedupe, cap to 3
    out = []
    for m in msgs:
        if m not in out:
            out.append(m)
    if not out:
        out = ["This file’s characteristics look unusual compared to safe files."]
    return out[:3]
