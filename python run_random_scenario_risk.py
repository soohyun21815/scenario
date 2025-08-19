# run_random_scenario_risk.py
import json, os, random, subprocess, sys, csv, glob
from pathlib import Path
import pandas as pd
import requests

# -------------------------
# 유틸: 파일 자동 탐색
# -------------------------
def find_file(candidates):
    """
    candidates: [정확한 경로 or 글롭패턴] 리스트
    1) 정확 경로 존재하면 그대로 사용
    2) 스크립트 폴더에서 글롭 검색
    3) 현재 작업 폴더에서 글롭 검색
    4) USERPROFILE/Desktop, OneDrive/Desktop 등 일반 위치들도 글롭 검색
    반환: 찾으면 str 경로, 못 찾으면 None
    """
    here = Path(__file__).resolve().parent
    cwd = Path.cwd()
    common_dirs = {here, cwd}

    # 환경에 따라 Desktop/OneDrive Desktop 후보 추가
    up = os.environ.get("USERPROFILE")
    if up:
        common_dirs.add(Path(up) / "Desktop")
        common_dirs.add(Path(up) / "바탕 화면")
    one = os.environ.get("OneDrive")
    if one:
        common_dirs.add(Path(one) / "Desktop")
        common_dirs.add(Path(one) / "바탕 화면")

    # 1) 정확 경로 검사
    for c in candidates:
        p = Path(c)
        if p.exists():
            return str(p)

    # 2) 글롭 검색 (스크립트 폴더부터)
    def glob_search(base: Path, pattern: str):
        return sorted(base.glob(pattern))

    # 후보 폴더들에서 모든 패턴 검색
    for base in list(common_dirs):
        for c in candidates:
            # 정확 경로가 아니라면 패턴으로 간주
            pat = c if any(ch in c for ch in "*?[]") else Path(c).name
            hits = glob_search(base, pat)
            if hits:
                return str(hits[-1])  # 가장 마지막(보통 최신/사전순 마지막)

    return None

# -------------------------
# 기본 후보(패턴) 정의
# -------------------------
BUNDLE_CANDIDATES = [
    # 정확 경로 후보 (원한다면 직접 넣어도 됨)
    r"C:\Users\psych\바탕 화면\시나리오\enterprise-attack-1.0.json",
    r"C:\Users\psych\OneDrive\바탕 화면\시나리오\enterprise-attack-1.0.json",
    # 패턴 후보
    "enterprise-attack*.json",
    "*enterprise-attack*.json",
]

MAPPING_CANDIDATES = [
    r"C:\Users\psych\바탕 화면\시나리오\Att&ckToCveMappings.csv",
    r"C:\Users\psych\OneDrive\바탕 화면\시나리오\Att&ckToCveMappings.csv",
    "Att&ckToCveMappings*.csv",
    "*Att&ckToCveMappings*.csv",
]

MAKE_SCENARIO_CANDIDATES = [
    r"C:\Users\psych\바탕 화면\시나리오\make_scenario.py",
    r"C:\Users\psych\OneDrive\바탕 화면\시나리오\make_scenario.py",
    "make_scenario.py",
    "*make_scenario.py",
]

# ---------------------------
# EPSS 관련
# ---------------------------
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

# ---------------------------
# 번들 로드 / 인덱싱
# ---------------------------
def load_bundle(bundle_path: str):
    with open(bundle_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("objects", [])

def index_tech(objects):
    name2tid, name2phases = {}, {}
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
        phases = []
        for ph in o.get("kill_chain_phases", []) or []:
            if ph.get("kill_chain_name") in ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]:
                phases.append(ph.get("phase_name"))
        if name and tid:
            name2tid[name.lower()] = tid
            name2phases[name.lower()] = phases
    return name2tid, name2phases

# ---------------------------
# 시나리오 생성 파일 호출
# ---------------------------
def run_make_scenario(make_script, start_name, bundle_path, path_len, csv_out):
    cmd = [
        sys.executable, make_script,
        start_name, "--bundle", bundle_path,
        "--path-len", str(path_len),
        "--csv", csv_out
    ]
    # 에러 메시지 확인을 위해 capture_output=True
    res = subprocess.run(cmd, text=True, capture_output=True)
    if res.returncode != 0:
        print("[make_scenario.py STDERR]")
        print(res.stderr)
        raise RuntimeError("make_scenario.py 실행 실패")

def read_steps_csv(csv_path):
    steps = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            steps.append({"step": int(row["step"]), "phase": row["phase"], "name": row["name"]})
    return steps

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

# ---------------------------
# 메인
# ---------------------------
def main():
    # 0) 필요 파일 자동 탐색
    bundle_path = find_file(BUNDLE_CANDIDATES)
    mapping_csv = find_file(MAPPING_CANDIDATES)
    make_script = find_file(MAKE_SCENARIO_CANDIDATES)

    missing = []
    if not bundle_path:  missing.append("enterprise-attack*.json")
    if not mapping_csv:  missing.append("Att&ckToCveMappings*.csv")
    if not make_script:  missing.append("make_scenario.py")
    if missing:
        print("[필수 파일을 찾지 못함]")
        for m in missing:
            print(f"- {m}")
        print("\n💡 해결:")
        print("1) 위 파일명을 현재 폴더(또는 스크립트 폴더/바탕 화면/OneDrive 바탕 화면)에 두거나")
        print("2) 코드 상단의 *_CANDIDATES 목록에 정확한 경로를 추가한 뒤 다시 실행")
        sys.exit(1)

    # 기본 파라미터(원하면 여기 수정)
    PATH_LEN = 6
    L, I = 3, 4  # 기본 방어/영향
    RAND_LI = False

    # 1) 번들 로드 & 인덱싱
    objs = load_bundle(bundle_path)
    name2tid, _ = index_tech(objs)
    if not name2tid:
        sys.exit("번들에서 기술을 찾지 못함")

    # 2) 랜덤 시작 + 시나리오 생성
    start_lower = random.choice(list(name2tid.keys()))
    start_disp = start_lower
    tmp_csv = "_tmp_steps.csv"
    run_make_scenario(make_script, start_disp, bundle_path, PATH_LEN, tmp_csv)

    steps = read_steps_csv(tmp_csv)
    if not steps:
        sys.exit("시나리오 생성 실패")

    # 3) TID→CVE 역매핑 만들고 EPSS 조회
    mapping_inv = read_mapping(mapping_csv)
    all_candidates = []
    for s in steps:
        nm = s["name"].lower()
        tid = name2tid.get(nm, "")
        cves = mapping_inv.get(tid, []) if tid else []
        all_candidates.extend(cves)

    epss_map = fetch_epss_bulk(all_candidates)

    # 4) 단계별 점수
    rows = []
    for s in steps:
        nm = s["name"].lower()
        tid = name2tid.get(nm, "")
        cves = mapping_inv.get(tid, []) if tid else []
        best_cve, best_epss, best_pct, best_date = None, 0.0, None, None
        for c in cves:
            m = epss_map.get(c)
            e = m["epss"] if m else 0.0
            if m and e >= best_epss:
                best_cve, best_epss = c, e
                best_pct, best_date = m["percentile"], m["date"]

        if RAND_LI:
            curL = random.randint(1,5)
            curI = random.randint(1,5)
        else:
            curL, curI = L, I

        E = epss_to_E(best_epss if best_cve else 0.0)
        pii_risk = E * (5 - curL) * curI
        V_norm = max(0.0, min(1.0, (5 - curL) / 4))
        I_norm = max(0.0, min(1.0, curI / 5))
        norm = (best_epss if best_cve else 0.0) * V_norm * I_norm

        rows.append({
            "step": s["step"],
            "phase": s["phase"],
            "technique": s["name"],
            "TID": tid,
            "CVE": best_cve or "",
            "EPSS": round(best_epss,4) if best_cve else "",
            "EPSS_percentile(%)": best_pct if best_cve else "",
            "EPSS_date": best_date if best_cve else "",
            "L": curL, "I": curI, "E(1~5)": E,
            "PII_Risk(0~125)": pii_risk,
            "NormRisk(0~1)": round(norm,6)
        })

    df = pd.DataFrame(rows)

    # 5) 요약(연쇄 결합)
    series_norm = 1.0
    for r in df["NormRisk(0~1)"]:
        r = float(r) if r != "" else 0.0
        series_norm *= (1.0 - r)
    series_norm = 1.0 - series_norm

    print(f'\n[랜덤 시작 기술] {start_disp}')
    print("\n[단계별 결과]")
    show_cols = ["step","phase","technique","TID","CVE","EPSS","E(1~5)","L","I","PII_Risk(0~125)","NormRisk(0~1)"]
    print(df[show_cols].to_string(index=False))

    print("\n[시나리오 요약]")
    print(f"- Steps: {len(df)}")
    print(f"- Sum PII_Risk(0~125): {int(df['PII_Risk(0~125)'].sum())}")
    print(f"- Avg Norm(0~1): {round(float(df['NormRisk(0~1)'].replace('',0).astype(float).mean()),6)}")
    print(f"- Max Norm(0~1): {round(float(df['NormRisk(0~1)'].replace('',0).astype(float).max()),6)}")
    print(f"- Series Norm(0~1): {round(series_norm,6)}  (~ {round(series_norm*100,2)}%)")

    # 임시 CSV 삭제
    try:
        os.remove(tmp_csv)
    except Exception:
        pass

if __name__ == "__main__":
    main()
