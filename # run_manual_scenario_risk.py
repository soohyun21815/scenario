# run_manual_scenario_risk_auto.py
import json, os, sys, csv, difflib
from pathlib import Path
import pandas as pd
import requests

# =========================
# 파일 자동 탐색 유틸
# =========================
def find_file(candidates):
    """
    candidates: [정확 경로 or 글롭 패턴]
    - 스크립트 폴더, 현재 폴더, USERPROFILE/Desktop/바탕 화면, OneDrive/Desktop/바탕 화면에서 탐색
    """
    here = Path(__file__).resolve().parent
    cwd = Path.cwd()
    bases = {here, cwd}
    up = os.environ.get("USERPROFILE")
    if up:
        bases.add(Path(up) / "Desktop")
        bases.add(Path(up) / "바탕 화면")
    one = os.environ.get("OneDrive")
    if one:
        bases.add(Path(one) / "Desktop")
        bases.add(Path(one) / "바탕 화면")

    # 1) 정확 경로 먼저 검사
    for c in candidates:
        p = Path(c)
        if p.exists():
            return str(p)

    # 2) 패턴 검색
    for base in list(bases):
        for c in candidates:
            pat = c if any(ch in c for ch in "*?[]") else Path(c).name
            hits = sorted(base.glob(pat))
            if hits:
                return str(hits[-1])
    return None

BUNDLE_CANDIDATES = [
    r"enterprise-attack-1.0.json",
    r"enterprise-attack*.json",
    r"*enterprise-attack*.json",
    r"C:\Users\psych\OneDrive\바탕 화면\시나리오\enterprise-attack-1.0.json",
    r"C:\Users\psych\바탕 화면\시나리오\enterprise-attack-1.0.json",
]
MAPPING_CANDIDATES = [
    r"Att&ckToCveMappings.csv",
    r"Att&ckToCveMappings*.csv",
    r"*Att&ckToCveMappings*.csv",
    r"C:\Users\psych\OneDrive\바탕 화면\시나리오\Att&ckToCveMappings.csv",
    r"C:\Users\psych\바탕 화면\시나리오\Att&ckToCveMappings.csv",
]

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
            out[cve] = {"epss": round(epss,4), "percentile": round(pct,2), "date": row.get("date")}
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
# ATT&CK 번들 파싱
# =========================
def load_bundle(bundle_path: str):
    with open(bundle_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("objects", [])

def index_tech(objects):
    """
    returns:
      name2tid: {lower(name)->TID}
      name2phase: {lower(name)->첫번째 phase_name}
      names_sorted: [기술명 원문] (출력/제안용)
    """
    name2tid = {}
    name2phase = {}
    names_sorted = []
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        if o.get("x_mitre_deprecated") or o.get("revoked"):
            continue
        name = (o.get("name") or "").strip()
        if not name:
            continue
        tid = ""
        for ref in o.get("external_references", []) or []:
            if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
                tid = (ref.get("external_id") or "").strip()
                break
        phase = None
        for ph in o.get("kill_chain_phases", []) or []:
            if ph.get("kill_chain_name") in ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]:
                phase = ph.get("phase_name")
                break
        if name and tid:
            key = name.lower()
            name2tid[key] = tid
            if phase:
                name2phase[key] = phase
            names_sorted.append(name)
    names_sorted.sort()
    return name2tid, name2phase, names_sorted

# =========================
# 매핑 CSV 로드 (TID -> [CVE])
# =========================
def read_mapping(mapping_csv):
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
            if not tid:
                continue
            inv.setdefault(tid, []).append(cve)
    return inv

# =========================
# L/I 자동 결정 (phase 휴리스틱)
# =========================
PHASE_LI = {
    "exfiltration":       (2, 5),
    "impact":             (2, 5),
    "credential-access":  (3, 4),
    "lateral-movement":   (3, 4),
    "privilege-escalation": (3, 4),
    "discovery":          (3, 2),
    # 기본값 그룹
    "initial-access":     (3, 3),
    "execution":          (3, 3),
    "persistence":        (3, 3),
    "defense-evasion":    (3, 3),
    "collection":         (3, 3),
    "command-and-control":(3, 3),
    "resource-development": (3, 3),
    "reconnaissance":     (3, 3),
}

def auto_LI(phase_name: str | None):
    if not phase_name:
        return 3, 3
    p = phase_name.strip().lower()
    return PHASE_LI.get(p, (3, 3))

# =========================
# 입력 & 계산
# =========================
def choose_from_candidates(query, names_sorted):
    cand = difflib.get_close_matches(query, names_sorted, n=5, cutoff=0.5)
    if not cand:
        print("  → 일치/유사 후보를 찾지 못함. 다시 입력해줘.")
        return None
    print("  비슷한 기술명 후보:")
    for i, nm in enumerate(cand, 1):
        print(f"   {i}. {nm}")
    pick = input("  번호 선택(Enter=1, 0=무시): ").strip()
    if pick == "":
        pick = "1"
    if not pick.isdigit():
        print("  → 유효하지 않아 1번 선택")
        pick = "1"
    k = int(pick)
    if k == 0:
        return None
    k = max(1, min(k, len(cand)))
    return cand[k-1]

def main():
    # 1) 필수 파일 찾기
    bundle_path = find_file(BUNDLE_CANDIDATES)
    mapping_csv = find_file(MAPPING_CANDIDATES)

    missing = []
    if not bundle_path:  missing.append("enterprise-attack*.json")
    if not mapping_csv:  missing.append("Att&ckToCveMappings*.csv")
    if missing:
        print("[필수 파일을 찾지 못함]")
        for m in missing:
            print(f"- {m}")
        print("\n해결: 파일을 현재 폴더/바탕 화면/OneDrive 바탕 화면으로 옮기거나, 코드 상단의 *_CANDIDATES에 정확 경로를 추가")
        sys.exit(1)

    # 2) 번들 인덱싱
    objs = load_bundle(bundle_path)
    name2tid, name2phase, names_sorted = index_tech(objs)
    if not name2tid:
        sys.exit("번들에서 기술을 찾지 못함")

    # 3) 시나리오 기술명 입력 (END로 종료)
    print("\n[시나리오 입력]  기술명을 한 줄씩 입력하세요. (끝내려면 END)")
    steps = []
    step_no = 1
    while True:
        raw = input(f" {step_no:02d}) 기술명: ").strip()
        if raw.upper() == "END":
            break
        if not raw:
            continue
        # 정확 일치 우선, 없으면 후보 제안
        key = raw.lower()
        if key not in name2tid:
            chosen = choose_from_candidates(raw, names_sorted)
            if not chosen:
                continue
            steps.append(chosen)
        else:
            # 원문명을 리스트에서 찾아 표시용으로 사용
            # (대소문자 보존을 위해 closest match)
            chosen = difflib.get_close_matches(raw, names_sorted, n=1, cutoff=0.0)
            steps.append(chosen[0] if chosen else raw)
        step_no += 1

    if not steps:
        print("입력된 기술이 없습니다. 종료합니다.")
        return

    # 4) 매핑 로드 & EPSS 벌크 조회
    mapping_inv = read_mapping(mapping_csv)

    # 후보 CVE 수집
    all_cves = []
    for nm in steps:
        tid = name2tid.get(nm.lower(), "")
        cves = mapping_inv.get(tid, []) if tid else []
        all_cves.extend(cves)
    epss_map = fetch_epss_bulk(all_cves)

    # 5) 점수 계산
    rows = []
    for idx, nm in enumerate(steps, 1):
        key = nm.lower()
        tid = name2tid.get(key, "")
        phase = name2phase.get(key)  # 없을 수도 있음

        # 자동 L/I
        L, I = auto_LI(phase)

        # 대표 CVE = EPSS 최고
        cves = mapping_inv.get(tid, []) if tid else []
        best_cve, best_epss, best_pct, best_date = None, 0.0, None, None
        for c in cves:
            m = epss_map.get(c)
            e = m["epss"] if m else 0.0
            if m and e >= best_epss:
                best_cve, best_epss = c, e
                best_pct, best_date = m["percentile"], m["date"]

        E = epss_to_E(best_epss if best_cve else 0.0)
        pii_risk = E * (5 - L) * I
        V_norm = max(0.0, min(1.0, (5 - L) / 4))
        I_norm = max(0.0, min(1.0, I / 5))
        norm = (best_epss if best_cve else 0.0) * V_norm * I_norm

        rows.append({
            "step": idx,
            "phase": phase or "",
            "technique": nm,
            "TID": tid,
            "CVE": best_cve or "",
            "EPSS": round(best_epss,4) if best_cve else "",
            "E(1~5)": E,
            "L": L, "I": I,
            "PII_Risk(0~125)": pii_risk,
            "NormRisk(0~1)": round(norm,6)
        })

    df = pd.DataFrame(rows)

    # 6) 시나리오 요약(연쇄 결합)
    series_norm = 1.0
    for r in df["NormRisk(0~1)"]:
        x = float(r) if str(r) != "" else 0.0
        series_norm *= (1.0 - x)
    series_norm = 1.0 - series_norm

    # 7) 출력
    print("\n[단계별 결과]")
    cols = ["step","phase","technique","TID","CVE","EPSS","E(1~5)","L","I","PII_Risk(0~125)","NormRisk(0~1)"]
    print(df[cols].to_string(index=False))

    print("\n[시나리오 요약]")
    print(f"- Steps: {len(df)}")
    print(f"- Sum PII_Risk(0~125): {int(df['PII_Risk(0~125)'].sum())}")
    print(f"- Avg Norm(0~1): {round(float(df['NormRisk(0~1)'].replace('',0).astype(float).mean()),6)}")
    print(f"- Max Norm(0~1): {round(float(df['NormRisk(0~1)'].replace('',0).astype(float).max()),6)}")
    print(f"- Series Norm(0~1): {round(series_norm,6)}  (~ {round(series_norm*100,2)}%)")

if __name__ == "__main__":
    main()
