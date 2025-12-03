import xml.etree.ElementTree as ET
import csv
import re
from pathlib import Path


def parse_evtx_to_xml(evtx_path: str):
    # Read as raw bytes first
    with open(evtx_path, "rb") as f:
        raw = f.read()

    # Heuristic: if there are lots of 0x00 bytes in the first chunk,
    # it's probably UTF-16 (like "<\x00E\x00v\x00e...").
    if b"\x00" in raw[:200]:
        try:
            content = raw.decode("utf-16")   # covers utf-16le/be with/without BOM
            print("[DEBUG] Decoded file as UTF-16")
        except UnicodeDecodeError:
            content = raw.decode("utf-8", errors="ignore")
            print("[DEBUG] Fallback: decoded as UTF-8 with ignore")
    else:
        content = raw.decode("utf-8", errors="ignore")
        print("[DEBUG] Decoded file as UTF-8")

    print(f"[DEBUG] File length (chars): {len(content)}")
    print(f"[DEBUG] Sample start: {content[:80]!r}")

    start = content.find("<Event")
    end = content.rfind("</Event>")

    if start == -1 or end == -1:
        print("[!] Could not find <Event> tags in decoded text – check export.")
        return []

    # Slice only the part that contains events
    body = content[start : end + len("</Event>")]

    # Strip the default xmlns from each <Event ...> to simplify parsing
    body_no_ns = re.sub(
        r"\sxmlns=['\"][^'\"]*['\"]",
        "",
        body
    )

    wrapped = "<Events>" + body_no_ns + "</Events>"

    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError as e:
        print(f"[!] Failed to parse wrapped XML: {e}")
        return []

    events = list(root.findall(".//Event"))
    print(f"[+] Parsed {len(events)} Sysmon events from XML")
    return events


def extract_behavior_features(evtx_xml_path: str, output_csv_path: str):
    events = parse_evtx_to_xml(evtx_xml_path)

    rows = []
    for ev in events:
        system = ev.find("System")
        event_id = None
        time_created = None

        if system is not None:
            # Event ID
            eid_elem = system.find("EventID")
            if eid_elem is not None and eid_elem.text is not None:
                event_id = int(eid_elem.text.strip())

            # TimeCreated/@SystemTime
            tc = system.find("TimeCreated")
            if tc is not None:
                time_created = tc.attrib.get("SystemTime")

        # Ignore events that don't have basic info
        if event_id is None or time_created is None:
            continue

        # Basic toy features – you can extend this later
        row = {
            "event_id": event_id,
            "timestamp": time_created,
        }

        # Example: add simple binary flags for certain Sysmon event types
        row["is_process_create"] = 1 if event_id == 1 else 0
        row["is_file_create"] = 1 if event_id == 11 else 0
        row["is_network_conn"] = 1 if event_id == 3 else 0

        rows.append(row)

    if not rows:
        print("[!] No events parsed – check your XML file.")
        return

    # Ensure output dir exists
    out_path = Path(output_csv_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(rows[0].keys())
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    # Adjust this path if needed – currently matches what you just used
    evtx_xml_path = r"C:\Users\richa\OneDrive\Documents\FYP2\datasets\behavioral\sysmon_log.xml"
    output_csv_path = r"C:\Users\richa\OneDrive\Documents\FYP2\datasets\behavioral\behavior_output.csv"

    print(f"[+] Loading EVTX XML: {evtx_xml_path}")
    extract_behavior_features(evtx_xml_path, output_csv_path)
