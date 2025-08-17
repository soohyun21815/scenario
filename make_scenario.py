import json
import argparse
import os
import glob
from collections import defaultdict

# ATT&CK Enterprise 전술(킬체인) 순서
PHASE_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# ---------------- 유틸 ----------------
def find_default_bundle():
    here = os.path.dirname(os.path.abspath(__file__))
    cands = sorted(glob.glob(os.path.join(here, "enterprise-attack*.json")))
    return cands[-1] if cands else None

def load_bundle(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("objects", [])

def phase_index(phases):
    idxs = [PHASE_ORDER.index(p) for p in phases if p in PHASE_ORDER]
    return min(idxs) if idxs else len(PHASE_ORDER)  # unknown은 맨 뒤

def read_weights_csv(path):
    """
    name,weight CSV → {lowercased_name: float_weight}
    예)
      name,weight
      PowerShell,0.8
      Spearphishing Attachment,0.9
    """
    if not path:
        return {}
    weights = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.lower().startswith("name"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                nm, w = parts[0], parts[1]
                try:
                    weights[nm.lower()] = float(w)
                except:
                    pass
    return weights

# ------------- STIX 인덱싱 -------------
def index_objects(objs):
    """
    반환:
      techniques_by_id: {stix_id: {name, phases}}
      techniques_by_name: {lower_name: {name, phases}}
      actors: {actor_id: {type, name}}
      relationships: list(SRO)
    """
    techniques_by_id = {}
    techniques_by_name = {}
    actors = {}
    relationships = []

    for o in objs:
        t = o.get("type")

        if t == "attack-pattern":
            if o.get("x_mitre_deprecated") or o.get("revoked"):
                continue

            name = o.get("name") or ""
            phases = []
            for ph in o.get("kill_chain_phases", []) or []:
                if ph.get("kill_chain_name") in ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]:
                    phases.append(ph.get("phase_name"))

            rec = {"name": name, "phases": phases or []}
            techniques_by_id[o["id"]] = rec
            if name:
                techniques_by_name[name.lower()] = rec

        elif t in ["intrusion-set", "malware", "tool", "campaign"]:
            if o.get("x_mitre_deprecated") or o.get("revoked"):
                continue
            actors[o["id"]] = {"type": t, "name": o.get("name") or ""}

        elif t == "relationship":
            relationships.append(o)

    return techniques_by_id, techniques_by_name, actors, relationships

# ------------- 진단/검색 -------------
def print_stats(tech_by_name, tech_by_id, actors, rels, sample=10):
    print(f"[stats] attack-pattern 개수: {len(tech_by_id)}")
    print(f"[stats] 기술 이름 개수    : {len(tech_by_name)}")
    print(f"[stats] actor 개수        : {len(actors)}")
    print(f"[stats] relationship 개수 : {len(rels)}")
    if tech_by_name:
        print("[stats] 샘플 기술명      :", ", ".join(list(tech_by_name.keys())[:sample]))

def find_name_like(tech_by_name, keyword):
    kw = keyword.lower()
    hits = []
    for lname, rec in tech_by_name.items():
        if kw in lname:
            hits.append(rec["name"])
    hits = sorted(set(hits))
    return hits

# ------------- 액터들의 연속 사용 패턴 → 전이 그래프 -------------
def build_transition_graph(rels, techniques_by_id, alpha=1.0):
    """
    actor별 uses 관계를 모아 킬체인 순으로 정렬 후,
    인접한 기술쌍 (A→B)에 대해 edges[A][B] += alpha
    키는 "기술 이름" (중복 이름이 있을 가능성은 낮지만, 필요시 stix_id로 바꿀 수 있음)
    """
    actor_to_techs = defaultdict(list)

    for r in rels:
        if r.get("relationship_type") == "uses":
            ap = techniques_by_id.get(r.get("target_ref"))
            if ap and ap.get("name"):
                actor_to_techs[r.get("source_ref")].append(ap)

    edges = defaultdict(lambda: defaultdict(float))  # from_name -> to_name -> weight
    for aps in actor_to_techs.values():
        # 중복 이름 제거
        seen = set()
        uniq = []
        for ap in aps:
            nm = ap["name"]
            if nm not in seen:
                uniq.append(ap)
                seen.add(nm)

        # 전술 순 정렬
        uniq.sort(key=lambda ap: (phase_index(ap["phases"]), ap["name"]))

        # 인접 쌍을 간선으로
        for i in range(len(uniq) - 1):
            a, b = uniq[i], uniq[i + 1]
            pa = phase_index(a["phases"])
            pb = phase_index(b["phases"])
            if pb < pa:  # 후퇴 방지
                continue
            edges[a["name"]][b["name"]] += float(alpha)

    return edges

# ------------- 시작 기술명 해석 -------------
def resolve_start_name(user_name, tech_by_name, edges, beta=1.0, weights=None):
    """
    - 정확히 존재하면 그대로
    - 없으면 부분일치 후보 중 '다음으로 이어지는 점수 합'이 최대인 이름 선택
      score = sum_{to}( edge_weight + beta * weight(to) )
    - 후보가 없으면 None
    """
    if not user_name:
        return None
    key = user_name.lower()
    if key in tech_by_name:
        return tech_by_name[key]["name"]

    # 부분일치 후보
    cands = find_name_like(tech_by_name, user_name)
    if not cands:
        return None

    best_name, best_score = None, float("-inf")
    for cand in cands:
        out = edges.get(cand, {})
        score = 0.0
        for nxt, ew in out.items():
            score += float(ew) + beta * float((weights or {}).get(nxt.lower(), 0.0))
        if score > best_score:
            best_name, best_score = cand, score

    # 만약 전이가 전혀 없으면 사전순으로 하나 선택
    if best_name is None:
        best_name = cands[0]
    return best_name

# ------------- 경로 생성 (greedy) -------------
def best_path_from_name(start_name, edges, tech_by_name, path_len=6, beta=1.0, weights=None):
    path = [start_name]
    visited = {start_name.lower()}
    cur = start_name

    for _ in range(path_len - 1):
        pa = phase_index(tech_by_name[cur.lower()]["phases"])
        cands = []
        for nxt, ew in edges.get(cur, {}).items():
            if nxt.lower() in visited or nxt.lower() not in tech_by_name:
                continue
            pb = phase_index(tech_by_name[nxt.lower()]["phases"])
            if pb < pa:
                continue
            score = float(ew) + beta * float((weights or {}).get(nxt.lower(), 0.0))
            cands.append((score, nxt))
        if not cands:
            break
        cands.sort(reverse=True)
        _, chosen = cands[0]
        path.append(chosen)
        visited.add(chosen.lower())
        cur = chosen

    # steps: [{phase, name}]
    steps = []
    for nm in path:
        rec = tech_by_name[nm.lower()]
        phase = next((p for p in rec["phases"] if p in PHASE_ORDER), "unknown")
        steps.append({"phase": phase, "name": rec["name"]})
    return steps

# ------------- CSV 저장 -------------
def save_csv(steps, out_path):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("step,phase,name\n")
        for i, s in enumerate(steps, 1):
            safe = (s["name"] or "").replace('"', "'")
            f.write(f'{i},{s["phase"]},"{safe}"\n')

# ------------- 메인 -------------
def main():
    p = argparse.ArgumentParser(description="ATT&CK technique-name path builder (no TID needed)")
    p.add_argument("tech", nargs="?", help='시작 "공격기법 이름" (예: PowerShell)')
    p.add_argument("--bundle", help="enterprise-attack.json 경로 (생략 시 같은 폴더 자동 탐색)")
    p.add_argument("--path-len", type=int, default=6, help="경로 길이 (기본 6)")
    p.add_argument("--weights", help="name,weight CSV (다음 기술 선호도)")
    p.add_argument("--alpha", type=float, default=1.0, help="간선(연속빈도) 가중치")
    p.add_argument("--beta", type=float, default=1.0, help="다음 기술 weight 가중치")

    # 진단/검색
    p.add_argument("--stats", action="store_true", help="번들 통계 출력")
    p.add_argument("--find", help="공격기법 이름 부분검색 (대소문자 무시)")

    # CSV 출력
    p.add_argument("--csv", help="CSV 저장 경로")
    args = p.parse_args()

    bundle_path = args.bundle or find_default_bundle()
    if not bundle_path or not os.path.exists(bundle_path):
        raise SystemExit("ATT&CK 번들을 찾지 못했음. --bundle로 경로를 주거나, 같은 폴더에 enterprise-attack*.json 을 두세요.")

    objs = load_bundle(bundle_path)
    tech_by_id, tech_by_name, actors, rels = index_objects(objs)

    if args.stats:
        print_stats(tech_by_name, tech_by_id, actors, rels)
        return

    if args.find:
        hits = find_name_like(tech_by_name, args.find)
        if not hits:
            print("검색 결과 없음.")
        else:
            for nm in hits[:200]:
                print(nm)
        return

    start_input = args.tech
    if not start_input:
        start_input = input('시작 "공격기법 이름"을 입력하세요 (예: PowerShell): ').strip()

    weights = read_weights_csv(args.weights)
    edges = build_transition_graph(rels, tech_by_id, alpha=args.alpha)

    # 이름 해석(정확/부분일치 허용)
    start_name = resolve_start_name(start_input, tech_by_name, edges, beta=args.beta, weights=weights)
    if not start_name:
        raise SystemExit(f'시작 공격기법을 찾지 못함: {start_input}\n힌트: python make_scenario.py --find "{start_input}"')

    steps = best_path_from_name(start_name, edges, tech_by_name, path_len=args.path_len, beta=args.beta, weights=weights)

    print(f'=== Path from: "{start_input}"  (start → "{steps[0]["name"]}") ===')
    for i, s in enumerate(steps, 1):
        print(f'{i:02d}. [{s["phase"]}] {s["name"]}')

    if args.csv:
        save_csv(steps, args.csv)
        print(f"[+] CSV saved: {args.csv}")

if __name__ == "__main__":
    main()
