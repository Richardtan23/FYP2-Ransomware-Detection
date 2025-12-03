# src/pe_static_extractor.py

import pefile
import pandas as pd
from typing import Dict, Any

from .static_model import get_static_feature_names


def _get_data_dir(pe: pefile.PE, name: str):
    """
    Helper: safely get (VirtualAddress, Size) from a given data directory.
    Returns (0.0, 0.0) on failure.
    """
    try:
        idx = pefile.DIRECTORY_ENTRY[name]
        entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        va = float(entry.VirtualAddress or 0)
        sz = float(entry.Size or 0)
        return va, sz
    except Exception:
        return 0.0, 0.0


def extract_pe_features(raw_bytes: bytes) -> pd.DataFrame:
    try:
        pe = pefile.PE(data=raw_bytes, fast_load=True)
    except pefile.PEFormatError:
        raise ValueError("File is not a valid PE executable (.exe/.dll).")

    feats = get_static_feature_names()
    row: Dict[str, float] = {f: 0.0 for f in feats}

    fh = pe.FILE_HEADER
    opt = pe.OPTIONAL_HEADER

    # ---- Simple header fields ----
    if "Machine" in row:
        row["Machine"] = float(getattr(fh, "Machine", 0) or 0)

    if "NumberOfSections" in row:
        row["NumberOfSections"] = float(getattr(fh, "NumberOfSections", 0) or 0)

    if "MajorLinkerVersion" in row:
        row["MajorLinkerVersion"] = float(getattr(opt, "MajorLinkerVersion", 0) or 0)

    if "MinorLinkerVersion" in row:
        row["MinorLinkerVersion"] = float(getattr(opt, "MinorLinkerVersion", 0) or 0)

    if "MajorImageVersion" in row:
        row["MajorImageVersion"] = float(getattr(opt, "MajorImageVersion", 0) or 0)

    if "MajorOSVersion" in row:
        # this corresponds to MajorOperatingSystemVersion in the PE
        row["MajorOSVersion"] = float(
            getattr(opt, "MajorOperatingSystemVersion", 0) or 0
        )

    if "SizeOfStackReserve" in row:
        row["SizeOfStackReserve"] = float(
            getattr(opt, "SizeOfStackReserve", 0) or 0
        )

    if "DllCharacteristics" in row:
        row["DllCharacteristics"] = float(
            getattr(opt, "DllCharacteristics", 0) or 0
        )

    # ---- Data directories ----
    # Debug
    dbg_rva, dbg_size = _get_data_dir(pe, "IMAGE_DIRECTORY_ENTRY_DEBUG")
    if "DebugRVA" in row:
        row["DebugRVA"] = dbg_rva
    if "DebugSize" in row:
        row["DebugSize"] = dbg_size

    # Export table
    exp_rva, exp_size = _get_data_dir(pe, "IMAGE_DIRECTORY_ENTRY_EXPORT")
    if "ExportRVA" in row:
        row["ExportRVA"] = exp_rva
    if "ExportSize" in row:
        row["ExportSize"] = exp_size

    # IAT (Import Address Table)
    iat_rva, _iat_size = _get_data_dir(pe, "IMAGE_DIRECTORY_ENTRY_IAT")
    if "IatVRA" in row:
        # Your feature name is "IatVRA" (looks like a typo in dataset),
        # we still fill it with the IAT VirtualAddress.
        row["IatVRA"] = iat_rva

    # Resources
    _res_rva, res_size = _get_data_dir(pe, "IMAGE_DIRECTORY_ENTRY_RESOURCE")
    if "ResourceSize" in row:
        row["ResourceSize"] = res_size

    # BitcoinAddresses - we can't reliably extract from the raw binary here,
    # so we keep it zero. This is consistent with many benign samples.
    if "BitcoinAddresses" in row:
        row["BitcoinAddresses"] = 0.0

    return pd.DataFrame([row])
