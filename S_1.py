# S_1.py  —  FIN7-style: spearphish → creds → email/cloud exfil
import json, os
from pathlib import Path
import pandas as pd
import requests

# =========================
# 설정(기본값은 자동 L/I가 없을 때만 사용)
# =========================
L_DEFAULT = 3
I_DEFAULT = 4

# 파일 자동 탐색 후보
BUNDLE_CANDIDATES = [
    r"C:\Users\psych\바탕 화면\시나리오\enterprise-attack-1.0.json",
    r"C:\Users\psych\OneDrive\바탕 화면\시나리오\enterprise-attack-1.0.json",
    "enterprise-attack*.json",
    "*enterprise-attack*.json",
]
MAPPING_CANDIDATES = [
    r"C:\Users\psych\바탕 화면\시나리오\Att&ckToCveMappings.csv",
    r"C:\Users\psych\OneDrive\바탕 화면\시나리오\Att&ckToCveMappings.csv",
    "Att&ckToCveMappings*.csv",
    "*Att&ckToCveMappings*.csv",
]

# 이 시나리오의 기술 순서(기술명은 번들에 있는 정확한 이름을 사용)
SCENARIO_TECHNIQUES = [
    "Spearphishing Attachment",
    "User Execution: Malicious File",
    "OS Credential Dumping",
    "Credentials from Web Browsers",
    "Email Collection",
    "Archive Collected Data",
    "Exfiltration to Cloud Storage",
]

# =========================
# 공통 유틸
# =========================
def find_file(candidates):
    here = Path(__file__).resolve().parent
    cwd = Path.cwd()
    search_dirs = {here, cwd}
    up = os.environ.get("USERPROFILE")
    if up:
        search_dirs.update({Path(up) / "Desktop", Path(up) / "바탕 화면"})
    one = os.environ.get("OneDrive")
    if one:
        search_dirs.update({Path(one) / "Desktop", Path(one) / "바탕 화면"})

    # 정확 경로
    for c in candidates:
        p = Path(c)
        if p.exists():
            return str(p)
    # 글롭 탐색
    for base in list(search_dirs):
        for c in candidates:
            pat = c if any(ch in c for ch in "*?[]") else Path(c).name
            hits = sorted(base.glob(pat))
            if hits:
                return str(hits[-1])
    return None

def load_bundle(bundle_path):
    with open(bundle_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("objects", [])

def index_tech(objects):
    """name→TID, name→phases(전술) 둘 다 리턴"""
    name2tid, name2phases = {}, {}
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("x_mitre_deprecated") or o.get("revoked"):
            continue
        name = (o.get("name") or "").strip()
        if not name:
            continue
        # TID
        tid = ""
        for ref in o.get("external_references", []) or []:
            if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
                tid = (ref.get("external_id") or "").strip()
                break
        # phases
        phases = []
        for ph in o.get("kill_chain_phases", []) or []:
            if ph.get("kill_chain_name") in ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]:
                phases.append(ph.get("phase_name"))
        if name and tid:
            name2tid[name.lower()] = tid
            name2phases[name.lower()] = phases
    return name2tid, name2phases

def read_mapping(mapping_csv):
    """Att&ckToCveMappings.csv 읽고 TID-> [CVE,...] 역매핑 생성"""
    df = pd.read_csv(mapping_csv)
    df.columns = df.columns.str.strip()
    if "CVE ID" in df.columns:
        df["CVE ID"] = (
            df["CVE ID"]
            .astype("string")
            .str.replace("\u2010|\u2011|\u2012|\u2013|\u2212", "-", regex=True)
            .str.strip()
            .str.upper()
        )
    tid_cols = [c for c in df.columns if c.upper() in ("TID_1", "TID_2")]
    inv = {}
    for _, r in df.iterrows():
        cve = str(r.get("CVE ID", "")).strip().upper()
        if not cve:
            continue
        for c in tid_cols:
            tid = str(r.get(c, "")).strip()
            if tid:
                inv.setdefault(tid, []).append(cve)
    return inv

# =========================
# EPSS
# =========================
def fetch_epss_bulk(cves):
    cves = [c for c in {c.strip().upper() for c in cves} if c]
    if not cves:
        return {}
    url = f"https://api.first.org/data/v1/epss?cve={','.join(cves)}"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        rows = r.json().get("data", [])
        out = {}
        for row in rows:
            cve = (row.get("cve") or "").upper()
            epss = float(row.get("epss", 0.0))
            pct = float(row.get("percentile", 0.0)) * 100
            out[cve] = {"epss": round(epss, 4), "percentile": round(pct, 2), "date": row.get("date")}
        return out
    except Exception:
        return {}

def epss_to_E(epss: float) -> int:
    if epss >= 0.9: return 5
    if epss >= 0.7: return 4
    if epss >= 0.4: return 3
    if epss >= 0.1: return 2
    return 1

# =========================
# [AUTO L/I] CSV 우선 + 전술 휴리스틱
# =========================
LI_L_CANDIDATES = [
    r"C:\Users\psych\바탕 화면\시나리오\tid_l_score.csv",
    r"C:\Users\psych\OneDrive\바탕 화면\시나리오\tid_l_score.csv",
    "tid_l_score*.csv", "*tid_l_score*.csv",
]
LI_I_CANDIDATES = [
    r"C:\Users\psych\바탕 화면\시나리오\tid_i_score.csv",
    r"C:\Users\psych\OneDrive\바탕 화면\시나리오\tid_i_score.csv",
    "tid_i_score*.csv", "*tid_i_score*.csv",
]

def try_load_tid_score_map(candidates, col_tid="tid", col_val="score"):
    path = find_file(candidates)
    if not path:
        return {}
    try:
        df = pd.read_csv(path)
        df.columns = df.columns.str.strip().str.lower()
        if col_tid not in df.columns:
            for c in df.columns:
                if c in ("tid", "technique_id", "external_id"):
                    col_tid = c; break
        if col_val not in df.columns:
            for c in df.columns:
                if c in ("score", "value", "l", "i"):
                    col_val = c; break
        mp = {}
        for _, r in df.iterrows():
            tid = str(r.get(col_tid, "")).strip().upper()
            try:
                val = int(float(r.get(col_val, "")))
            except:
                continue
            if tid and 1 <= val <= 5:
                mp[tid] = val
        return mp
    except Exception:
        return {}

_TID_L_MAP = None
_TID_I_MAP = None
def load_li_maps_once():
    global _TID_L_MAP, _TID_I_MAP
    if _TID_L_MAP is None:
        _TID_L_MAP = try_load_tid_score_map(LI_L_CANDIDATES, col_tid="tid", col_val="l")
    if _TID_I_MAP is None:
        _TID_I_MAP = try_load_tid_score_map(LI_I_CANDIDATES, col_tid="tid", col_val="i")

I_BASE_BY_TACTIC = {
    "exfiltration": 5,
    "collection": 4,
    "credential-access": 4,
    "lateral-movement": 3,
    "privilege-escalation": 3,
    "defense-evasion": 3,
    "execution": 3,
    "initial-access": 3,
    "command-and-control": 3,
    "persistence": 3,
    "discovery": 2,
    "resource-development": 2,
    "reconnaissance": 2,
}
L_BASE_BY_TACTIC = {
    "exfiltration": 2,
    "collection": 2,
    "credential-access": 2,
    "defense-evasion": 2,
    "privilege-escalation": 2,
    "lateral-movement": 3,
    "initial-access": 3,
    "execution": 3,
    "command-and-control": 3,
    "persistence": 3,
    "discovery": 4,
    "resource-development": 4,
    "reconnaissance": 4,
}

def phases_for_name(tech_name: str, name2phases: dict):
    return [p.lower() for p in name2phases.get(tech_name.lower(), [])]

def li_from_tactics(tactics: list):
    if not tactics:
        return (L_DEFAULT, I_DEFAULT)
    I_vals = [I_BASE_BY_TACTIC.get(t, I_DEFAULT) for t in tactics]
    L_vals = [L_BASE_BY_TACTIC.get(t, L_DEFAULT) for t in tactics]
    I = max(I_vals) if I_vals else I_DEFAULT
    L = min(L_vals) if L_vals else L_DEFAULT
    I = max(1, min(5, int(I)))
    L = max(1, min(5, int(L)))
    return (L, I)

def get_LI_auto(tid: str, name2phases: dict, tech_name: str = ""):
    load_li_maps_once()
    # 1) CSV 우선
    if tid:
        if tid in _TID_L_MAP and tid in _TID_I_MAP:
            return (_TID_L_MAP[tid], _TID_I_MAP[tid])
        if tid in _TID_L_MAP:
            tactics = phases_for_name(tech_name, name2phases)
            _, I_auto = li_from_tactics(tactics)
            return (_TID_L_MAP[tid], I_auto)
        if tid in _TID_I_MAP:
            tactics = phases_for_name(tech_name, name2phases)
            L_auto, _ = li_from_tactics(tactics)
            return (L_auto, _TID_I_MAP[tid])
    # 2) 전술 휴리스틱
    tactics = phases_for_name(tech_name, name2phases)
    return li_from_tactics(tactics)

# =========================
# 메인
# =========================
def main():
    bundle_path = find_file(BUNDLE_CANDIDATES)
    mapping_csv = find_file(MAPPING_CANDIDATES)
    if not bundle_path or not mapping_csv:
        print("[필수 파일을 찾지 못함]")
        if not bundle_path: print("- enterprise-attack*.json")
        if not mapping_csv: print("- Att&ckToCveMappings*.csv")
        return

    objs = load_bundle(bundle_path)
    name2tid, name2phases = index_tech(objs)
    mapping_inv = read_mapping(mapping_csv)

    rows = []
    all_cve_candidates = []
    tech_list = []
    for nm in SCENARIO_TECHNIQUES:
        tid = name2tid.get(nm.lower(), "")
        tech_list.append((nm, tid))
        if tid and tid in mapping_inv:
            all_cve_candidates.extend(mapping_inv[tid])

    # 단계에 필요한 CVE EPSS를 한 번에 조회
    epss_map = fetch_epss_bulk(all_cve_candidates)

    for i, (tech_name, tid) in enumerate(tech_list, start=1):
        cves = mapping_inv.get(tid, []) if tid else []
        best_cve, best_epss, best_pct, best_date = "", 0.0, "", ""
        for c in cves:
            m = epss_map.get(c)
            e = m["epss"] if m else 0.0
            if m and e >= best_epss:
                best_cve, best_epss = c, e
                best_pct, best_date = m["percentile"], m["date"]

        # ← 여기! 자동 L/I
        L, I = get_LI_auto(tid, name2phases, tech_name=tech_name)

        E = epss_to_E(best_epss if best_cve else 0.0)
        pii_risk = E * (5 - L) * I
        V_norm = max(0.0, min(1.0, (5 - L) / 4))
        I_norm = max(0.0, min(1.0, I / 5))
        norm = (best_epss if best_cve else 0.0) * V_norm * I_norm

        rows.append({
            "step": i,
            "technique": tech_name,
            "TID": tid,
            "CVE": best_cve,
            "EPSS": round(best_epss, 4) if best_cve else "",
            "EPSS_percentile(%)": best_pct if best_cve else "",
            "EPSS_date": best_date if best_cve else "",
            "E(1~5)": E, "L": L, "I": I,
            "PII_Risk(0~125)": pii_risk,
            "NormRisk(0~1)": round(norm, 6),
        })

    df = pd.DataFrame(rows)

    # 연쇄 결합(시리즈 리스크)
    series_norm = 1.0
    for r in df["NormRisk(0~1)"]:
        r = float(r) if r != "" else 0.0
        series_norm *= (1.0 - r)
    series_norm = 1.0 - series_norm

    show_cols = ["step","technique","TID","CVE","EPSS","E(1~5)","L","I","PII_Risk(0~125)","NormRisk(0~1)"]
    print("\n[Scenario] FIN7-style: spearphish → creds → email/cloud exfil")
    print(df[show_cols].to_string(index=False))
    print("\n[Summary]")
    print(f"- Steps: {len(df)}")
    print(f"- Sum PII_Risk: {int(df['PII_Risk(0~125)'].sum())}")
    print(f"- Avg Norm: {round(float(df['NormRisk(0~1)'].replace('',0).astype(float).mean()),6)}")
    print(f"- Max Norm: {round(float(df['NormRisk(0~1)'].replace('',0).astype(float).max()),6)}")
    print(f"- Series Norm: {round(series_norm,6)} (~ {round(series_norm*100,2)}%)")

if __name__ == "__main__":
    main()
