"""
FuzzyShield — Behavioral Malware Classifier
Fuzzy Logic Engine v2.0

Output directory structure:
  output/
  ├── scenarios/      ← preset / custom scenario runs
  ├── pid_sessions/   ← each PID monitoring session in its own timestamped folder
  └── analysis/       ← 3D rule surface plots and standalone analysis

Usage:
  python fuzzy_shield.py                          # interactive mode
  python fuzzy_shield.py --scenario ransomware
  python fuzzy_shield.py --all                    # all preset scenarios
  python fuzzy_shield.py --report                 # all scenarios + 3D surfaces
  python fuzzy_shield.py --pid <PID>              # live process monitoring
  python fuzzy_shield.py --pid <PID> --interval 5 --checks 12

Simulator (separate script):
  sim/malware_sim.py --type ransomware|trojan|cryptominer|benign [--duration 120]

Dependencies:
  pip install numpy matplotlib scikit-fuzzy psutil
"""

import argparse
import os
import math
import time
import datetime
import random
import numpy as np
import matplotlib
matplotlib.use("Agg")           # headless – saves PNGs instead of opening windows
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import skfuzzy as fuzz
from skfuzzy import control as ctrl

try:
    import psutil
    _PSUTIL = True
except ImportError:
    _PSUTIL = False

# ══════════════════════════════════════════════════════════════════
# OUTPUT DIRECTORY MANAGEMENT
# ══════════════════════════════════════════════════════════════════

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_OUT_ROOT     = os.path.join(_PROJECT_ROOT, "output")

def _ts() -> str:
    """Current timestamp string: YYYYMMDD_HHMMSS"""
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def _outdir(subdir: str) -> str:
    """Return absolute path to output/<subdir>, creating it if needed."""
    path = os.path.join(_OUT_ROOT, subdir)
    os.makedirs(path, exist_ok=True)
    return path

def _scenario_path(name: str, kind: str) -> str:
    """output/scenarios/<name>_<timestamp>_<kind>.png"""
    d = _outdir("scenarios")
    return os.path.join(d, f"{name}_{_ts()}_{kind}.png")

def _analysis_path(name: str) -> str:
    """output/analysis/<name>_<timestamp>.png"""
    d = _outdir("analysis")
    return os.path.join(d, f"{name}_{_ts()}.png")

def _pid_session_dir(pid: int, proc_name: str, session_ts: str) -> str:
    """output/pid_sessions/<timestamp>_pid<N>_<procname>/  — created once per session."""
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in proc_name)[:20]
    folder = f"{session_ts}_pid{pid}_{safe_name}"
    return _outdir(os.path.join("pid_sessions", folder))

# ══════════════════════════════════════════════════════════════════
# 1. UNIVERSE DEFINITIONS
# ══════════════════════════════════════════════════════════════════

u_cpu    = np.linspace(0,   100,  500)   # CPU usage          (%)
u_mem    = np.linspace(0,  2048,  500)   # Memory RSS         (MB)
u_fwrite = np.linspace(0,   200,  500)   # File write rate    (MB/s)
u_fread  = np.linspace(0,   200,  500)   # File read rate     (MB/s)
u_nettx  = np.linspace(0, 10000,  500)   # Network upload     (KB/s)
u_netrx  = np.linspace(0, 10000,  500)   # Network download   (KB/s)
u_ext    = np.linspace(0,    50,  500)   # Unique extensions  (count)
u_conn   = np.linspace(0,   500,  500)   # Active connections (count)
u_ent    = np.linspace(0,     8,  500)   # Output entropy     (bits/byte)
u_priv   = np.linspace(0,    20,  500)   # Priv-esc attempts  (count)
u_out    = np.linspace(0,     1,  500)   # Output universes   (probability)

# ══════════════════════════════════════════════════════════════════
# 2. ANTECEDENTS (INPUTS)
# ══════════════════════════════════════════════════════════════════

cpu    = ctrl.Antecedent(u_cpu,    'cpu')
mem    = ctrl.Antecedent(u_mem,    'mem')
fwrite = ctrl.Antecedent(u_fwrite, 'fwrite')
file_read  = ctrl.Antecedent(u_fread,  'file_read')
nettx  = ctrl.Antecedent(u_nettx,  'nettx')
netrx  = ctrl.Antecedent(u_netrx,  'netrx')
ext    = ctrl.Antecedent(u_ext,    'ext')
conn   = ctrl.Antecedent(u_conn,   'conn')
ent    = ctrl.Antecedent(u_ent,    'ent')
priv   = ctrl.Antecedent(u_priv,   'priv')

# ── CPU  ──────────────────────────────────────────────────────────
cpu['idle']     = fuzz.trapmf(u_cpu, [ 0,  0, 10, 20])
cpu['low']      = fuzz.trapmf(u_cpu, [10, 20, 30, 45])
cpu['moderate'] = fuzz.trimf (u_cpu, [35, 50, 65])
cpu['high']     = fuzz.trapmf(u_cpu, [55, 70, 80, 90])
cpu['extreme']  = fuzz.trapmf(u_cpu, [82, 92,100,100])

# ── Memory ───────────────────────────────────────────────────────
mem['tiny']   = fuzz.trapmf(u_mem, [   0,   0,  64, 150])
mem['small']  = fuzz.trapmf(u_mem, [ 100, 180, 280, 400])
mem['medium'] = fuzz.trimf (u_mem, [ 300, 512, 800])
mem['large']  = fuzz.trapmf(u_mem, [ 700, 900,1200,1500])
mem['huge']   = fuzz.trapmf(u_mem, [1300,1600,2048,2048])

# ── File Write ───────────────────────────────────────────────────
fwrite['none']     = fuzz.trapmf(u_fwrite, [  0,  0,  2,  6])
fwrite['low']      = fuzz.trapmf(u_fwrite, [  3, 10, 20, 35])
fwrite['moderate'] = fuzz.trimf (u_fwrite, [ 25, 50, 80])
fwrite['high']     = fuzz.trapmf(u_fwrite, [ 65,100,140,170])
fwrite['extreme']  = fuzz.trapmf(u_fwrite, [150,175,200,200])

# ── File Read ────────────────────────────────────────────────────
file_read['none']     = fuzz.trapmf(u_fread, [  0,  0,  3,  8])
file_read['low']      = fuzz.trapmf(u_fread, [  5, 15, 30, 50])
file_read['moderate'] = fuzz.trimf (u_fread, [ 35, 60, 95])
file_read['high']     = fuzz.trapmf(u_fread, [ 80,110,150,175])
file_read['extreme']  = fuzz.trapmf(u_fread, [160,180,200,200])

# ── Network TX ───────────────────────────────────────────────────
nettx['silent']   = fuzz.trapmf(u_nettx, [    0,    0,   10,   40])
nettx['low']      = fuzz.trapmf(u_nettx, [   20,   80,  200,  400])
nettx['moderate'] = fuzz.trimf (u_nettx, [  300,  700, 1400])
nettx['high']     = fuzz.trapmf(u_nettx, [ 1000, 2000, 4000, 6000])
nettx['flood']    = fuzz.trapmf(u_nettx, [ 4500, 7000,10000,10000])

# ── Network RX ───────────────────────────────────────────────────
netrx['silent']   = fuzz.trapmf(u_netrx, [    0,    0,   15,   50])
netrx['low']      = fuzz.trapmf(u_netrx, [   30,  100,  250,  500])
netrx['moderate'] = fuzz.trimf (u_netrx, [  400,  900, 1800])
netrx['high']     = fuzz.trapmf(u_netrx, [ 1400, 2500, 5000, 7000])
netrx['flood']    = fuzz.trapmf(u_netrx, [ 5500, 8000,10000,10000])

# ── Unique Extensions ────────────────────────────────────────────
ext['single']  = fuzz.trapmf(u_ext, [ 0,  0,  2,  4])
ext['few']     = fuzz.trapmf(u_ext, [ 2,  5, 10, 15])
ext['several'] = fuzz.trimf (u_ext, [10, 18, 28])
ext['many']    = fuzz.trapmf(u_ext, [22, 32, 42, 48])
ext['mass']    = fuzz.trapmf(u_ext, [40, 46, 50, 50])

# ── Active Connections ───────────────────────────────────────────
conn['none']     = fuzz.trapmf(u_conn, [  0,  0,  2,  6])
conn['few']      = fuzz.trapmf(u_conn, [  3, 10, 25, 50])
conn['moderate'] = fuzz.trimf (u_conn, [ 35, 80,150])
conn['many']     = fuzz.trapmf(u_conn, [120,200,320,420])
conn['swarm']    = fuzz.trapmf(u_conn, [350,430,500,500])

# ── Output Entropy ───────────────────────────────────────────────
ent['ordered'] = fuzz.trapmf(u_ent, [0.0, 0.0, 1.5, 2.5])
ent['low']     = fuzz.trapmf(u_ent, [1.8, 2.8, 3.6, 4.5])
ent['medium']  = fuzz.trimf (u_ent, [3.8, 5.0, 6.2])
ent['high']    = fuzz.trapmf(u_ent, [5.5, 6.5, 7.2, 7.8])
ent['max']     = fuzz.trapmf(u_ent, [7.2, 7.7, 8.0, 8.0])

# ── Privilege Escalation ─────────────────────────────────────────
priv['none']     = fuzz.trapmf(u_priv, [ 0,  0,  0,  1])
priv['low']      = fuzz.trapmf(u_priv, [ 0,  1,  2,  4])
priv['moderate'] = fuzz.trimf (u_priv, [ 3,  6, 10])
priv['high']     = fuzz.trapmf(u_priv, [ 8, 12, 16, 18])
priv['extreme']  = fuzz.trapmf(u_priv, [16, 18, 20, 20])

# ══════════════════════════════════════════════════════════════════
# 3. CONSEQUENTS (OUTPUTS)
# ══════════════════════════════════════════════════════════════════

ransomware  = ctrl.Consequent(u_out, 'ransomware',  defuzzify_method='centroid')
trojan      = ctrl.Consequent(u_out, 'trojan',      defuzzify_method='centroid')
cryptominer = ctrl.Consequent(u_out, 'cryptominer', defuzzify_method='centroid')

for out_var in [ransomware, trojan, cryptominer]:
    out_var['none']     = fuzz.trapmf(u_out, [0.00, 0.00, 0.05, 0.15])
    out_var['trace']    = fuzz.trapmf(u_out, [0.05, 0.15, 0.25, 0.35])
    out_var['low']      = fuzz.trapmf(u_out, [0.25, 0.35, 0.45, 0.55])
    out_var['medium']   = fuzz.trimf (u_out, [0.45, 0.60, 0.75])
    out_var['high']     = fuzz.trapmf(u_out, [0.65, 0.75, 0.85, 0.92])
    out_var['critical'] = fuzz.trapmf(u_out, [0.85, 0.93, 1.00, 1.00])

# ══════════════════════════════════════════════════════════════════
# 4. RULE BASE  (34 rules)
# ══════════════════════════════════════════════════════════════════

rules = [
    # ── RANSOMWARE (7 rules) ──────────────────────────────────────
    ctrl.Rule(fwrite['extreme'] & ext['many']    & ent['max'],
              (ransomware['critical'], trojan['none'], cryptominer['none'])),

    ctrl.Rule(fwrite['high']    & ext['many']    & ent['high'],
              (ransomware['high'],     trojan['trace'], cryptominer['none'])),

    ctrl.Rule(fwrite['extreme'] & ent['high']    & conn['few'],
              (ransomware['high'],     trojan['trace'], cryptominer['none'])),

    ctrl.Rule(fwrite['high']    & ext['several'] & ent['high'],
              (ransomware['medium'],   trojan['trace'], cryptominer['none'])),

    ctrl.Rule(fwrite['extreme'] & ext['mass']    & cpu['high'],
              (ransomware['high'],     trojan['none'],  cryptominer['none'])),

    ctrl.Rule(ent['max']        & fwrite['high'] & priv['moderate'],
              (ransomware['high'],     trojan['trace'], cryptominer['none'])),

    ctrl.Rule(fwrite['moderate']& ext['many']    & ent['medium'],
              (ransomware['medium'],   trojan['trace'], cryptominer['none'])),

    # ── TROJAN (8 rules) ──────────────────────────────────────────
    ctrl.Rule(nettx['high']     & conn['many']   & priv['high'],
              (ransomware['none'],  trojan['critical'], cryptominer['none'])),

    ctrl.Rule(nettx['flood']    & conn['swarm'],
              (ransomware['none'],  trojan['critical'], cryptominer['none'])),

    ctrl.Rule(nettx['high']     & netrx['high']  & conn['many'],
              (ransomware['trace'], trojan['high'],     cryptominer['trace'])),

    ctrl.Rule(conn['many']      & priv['high']   & cpu['low'],
              (ransomware['none'],  trojan['high'],     cryptominer['none'])),

    ctrl.Rule(nettx['moderate'] & conn['many']   & priv['extreme'],
              (ransomware['trace'], trojan['high'],     cryptominer['none'])),

    ctrl.Rule(netrx['high']     & conn['many']   & fwrite['low'],
              (ransomware['none'],  trojan['medium'],   cryptominer['trace'])),

    ctrl.Rule(nettx['flood']    & priv['extreme'],
              (ransomware['none'],  trojan['critical'], cryptominer['none'])),

    ctrl.Rule(conn['moderate']  & nettx['high']  & priv['moderate'],
              (ransomware['none'],  trojan['medium'],   cryptominer['trace'])),

    # ── CRYPTOMINER (8 rules) ─────────────────────────────────────
    # R16: extreme CPU + no file writes + moderate pool traffic → critical
    ctrl.Rule(cpu['extreme']    & fwrite['none'] & nettx['moderate'],
              (ransomware['none'],  trojan['none'],  cryptominer['critical'])),

    # R17: extreme CPU + large memory footprint + moderate network → critical
    ctrl.Rule(cpu['extreme']    & mem['large']   & nettx['moderate'],
              (ransomware['none'],  trojan['none'],  cryptominer['critical'])),

    # R18: high CPU + moderate pool traffic + few connections + no file writes → high
    # fwrite=none discriminates update/compile jobs (which write extensively) from miners
    ctrl.Rule(cpu['high']       & nettx['moderate'] & conn['few'] & fwrite['none'],
              (ransomware['none'],  trojan['trace'], cryptominer['high'])),

    # R19: extreme CPU + no file writes + few connections + low entropy → high
    # low entropy (1.8-4.5 bits/B): structured pool protocol output, not file encryption
    # conn['few'] distinguishes from trojan (which also has extreme CPU via threads + swarm conns)
    ctrl.Rule(cpu['extreme']    & fwrite['none'] & conn['few'] & ent['low'],
              (ransomware['none'],  trojan['none'],  cryptominer['high'])),

    # R20: high CPU + huge memory + moderate network → high
    ctrl.Rule(cpu['high']       & mem['huge']    & nettx['moderate'],
              (ransomware['none'],  trojan['none'],  cryptominer['high'])),

    # R21: moderate CPU + moderate network + moderate connections + no file writes → low
    # fwrite=none required: avoids flagging databases/web servers that write to disk.
    # Output downgraded medium→low so light miners score SUSPICIOUS rather than LIKELY THREAT.
    ctrl.Rule(cpu['moderate']   & nettx['moderate'] & conn['moderate'] & fwrite['none'],
              (ransomware['none'],  trojan['trace'], cryptominer['low'])),

    # R22: extreme CPU (all cores) + few connections + no file writes → high
    # cpu['extreme'] used here (not 'high') because maxing all cores gives 100% → extreme
    ctrl.Rule(cpu['extreme']    & conn['few']    & fwrite['none'],
              (ransomware['none'],  trojan['none'],  cryptominer['high'])),

    # R24: extreme CPU + no file writes + few connections + ordered entropy → critical
    # Strongest "offline miner" fingerprint: all-core CPU, zero disk, minimal structured traffic
    ctrl.Rule(cpu['extreme']    & fwrite['none'] & conn['few']    & ent['ordered'],
              (ransomware['none'],  trojan['none'],  cryptominer['critical'])),

    # R25: high write rate + max entropy + several extensions → ransomware['high']
    # fwrite['high'] (65-140 MB/s): rapid multi-file overwrite with cryptographically-random bytes
    # ent['max'] (>7.7 bits/B): pure-random output — distinguishes encryption from compression
    ctrl.Rule(fwrite['high']     & ent['max']  & ext['several'],
              (ransomware['high'],   trojan['none'],  cryptominer['none'])),

    # R26: moderate write rate + max entropy + several extensions → ransomware['high']
    # Covers slower ransomware variants (ext4-cached writes, CPU-intensive encryption)
    ctrl.Rule(fwrite['moderate'] & ent['max']  & ext['several'],
              (ransomware['high'],   trojan['none'],  cryptominer['none'])),

    # R27: high write + max entropy + no connections → ransomware['medium']
    # Offline encryption (no C2): high certainty of file encryption, no exfiltration detected
    ctrl.Rule(fwrite['high']     & ent['max']  & conn['none'],
              (ransomware['medium'], trojan['none'],  cryptominer['none'])),

    # ── MIXED / AMBIGUOUS (5 rules) ───────────────────────────────
    ctrl.Rule(cpu['high']       & fwrite['high'] & nettx['high'],
              (ransomware['medium'], trojan['medium'], cryptominer['trace'])),

    ctrl.Rule(priv['moderate']  & ent['high']    & nettx['moderate'],
              (ransomware['medium'], trojan['medium'], cryptominer['trace'])),

    ctrl.Rule(priv['extreme']   & ent['max']     & conn['many'],
              (ransomware['high'],   trojan['high'],   cryptominer['none'])),

    # ── FILE READ — encrypt & exfiltration patterns (3 rules) ────
    # R28: extreme write + low read + max entropy = ransomware (overwrite with encrypted data)
    ctrl.Rule(fwrite['extreme'] & file_read['low']      & ent['max'],
              (ransomware['critical'], trojan['none'],   cryptominer['none'])),

    # R29: moderate read + extreme write + mass extensions = ransomware (bulk re-encrypt)
    ctrl.Rule(file_read['moderate'] & fwrite['extreme'] & ext['mass'],
              (ransomware['high'],    trojan['trace'],   cryptominer['none'])),

    # R30: low read + high nettx + many conn = trojan (read local data, exfiltrate)
    ctrl.Rule(file_read['low']    & nettx['high']       & conn['many'],
              (ransomware['trace'],   trojan['high'],    cryptominer['none'])),

    # ── BENIGN (2 rules) ──────────────────────────────────────────
    ctrl.Rule(cpu['idle']    & fwrite['none'] & nettx['silent'] & conn['none'],
              (ransomware['none'], trojan['none'], cryptominer['none'])),

    ctrl.Rule(cpu['idle']    & ent['ordered'] & priv['none']   & ext['single'],
              (ransomware['none'], trojan['none'], cryptominer['none'])),
]

# ══════════════════════════════════════════════════════════════════
# 5. CONTROL SYSTEM
# ══════════════════════════════════════════════════════════════════

system = ctrl.ControlSystem(rules)
sim    = ctrl.ControlSystemSimulation(system)

# ══════════════════════════════════════════════════════════════════
# 6. SCENARIOS
# ══════════════════════════════════════════════════════════════════

def _mixed_scenario() -> dict:
    """Generate a randomised mixed-threat profile each call.

    Ranges are anchored inside membership-function overlap zones so that
    multiple competing rules always fire, producing genuinely ambiguous
    (non-zero) fuzzy scores with a different dominant threat each run.

    Key anchoring decisions:
      nettx  500-4500  → always inside nettx['moderate'] or nettx['high']
      conn   30-260    → spans conn['few'] through conn['many']
      priv   3-14      → inside priv['moderate'] / priv['high']  (unlocks trojan rules)
      fwrite 10-120    → inside fwrite['low'] through fwrite['high'] (unlocks ransomware rules)
      ent    3.0-6.8   → spans ent['low'] / ent['medium'] / ent['high']
    """
    def u(lo, hi):
        return round(random.uniform(lo, hi), 2)

    return dict(
        cpu       = u(35,  88),    # moderate → extreme
        mem       = u(150, 1400),  # small → large
        fwrite    = u(10,  120),   # low → high
        file_read = u(5,   70),    # low → moderate
        nettx     = u(500, 4500),  # moderate → high  (always triggers network rules)
        netrx     = u(300, 3000),
        ext       = u(4,   32),    # few → many
        conn      = u(30,  260),   # few → many      (always triggers conn rules)
        ent       = u(3.0, 6.8),   # low → high      (always triggers ent rules)
        priv      = u(3,   14),    # moderate → high  (always triggers priv rules)
    )

SCENARIOS = {
    "ransomware":  dict(cpu=75, mem=480,  fwrite=160, file_read=40,  nettx=80,   netrx=50,  ext=45, conn=12,  ent=7.8, priv=3),
    "trojan":      dict(cpu=18, mem=210,  fwrite=8,   file_read=12,  nettx=4200, netrx=3500,ext=5,  conn=320, ent=3.2, priv=14),
    "cryptominer": dict(cpu=96, mem=1400, fwrite=2,   file_read=5,   nettx=600,  netrx=200, ext=2,  conn=20,  ent=2.8, priv=1),
    "benign":      dict(cpu=12, mem=180,  fwrite=4,   file_read=8,   nettx=60,   netrx=90,  ext=3,  conn=4,   ent=2.1, priv=0),
    "mixed":       _mixed_scenario,   # callable — generates fresh random values each run
}

# ══════════════════════════════════════════════════════════════════
# 7. INFERENCE
# ══════════════════════════════════════════════════════════════════

def run_inference(inputs: dict) -> dict:
    """Run fuzzy inference and return defuzzified scores."""
    valid_keys = {a.label for a in sim.ctrl.antecedents}
    for key, val in inputs.items():
        if key in valid_keys:
            sim.input[key] = float(val)
    try:
        sim.compute()
    except Exception:
        pass  # no rules fired — outputs default to 0.0
    return {
        "ransomware":  round(sim.output.get("ransomware",  0.0), 4),
        "trojan":      round(sim.output.get("trojan",      0.0), 4),
        "cryptominer": round(sim.output.get("cryptominer", 0.0), 4),
    }

def get_memberships(inputs: dict) -> dict:
    """Return all membership degrees for each input variable."""
    sets_def = {
        "cpu":    (u_cpu,    cpu),
        "mem":    (u_mem,    mem),
        "fwrite": (u_fwrite, fwrite),
        "file_read":  (u_fread,  file_read),
        "nettx":  (u_nettx,  nettx),
        "netrx":  (u_netrx,  netrx),
        "ext":    (u_ext,    ext),
        "conn":   (u_conn,   conn),
        "ent":    (u_ent,    ent),
        "priv":   (u_priv,   priv),
    }
    result = {}
    for var_name, (universe, var_obj) in sets_def.items():
        val = inputs[var_name]
        result[var_name] = {}
        for term_name, mf in var_obj.terms.items():
            deg = float(fuzz.interp_membership(universe, mf.mf, val))
            result[var_name][term_name] = round(deg, 4)
    return result

_THREAT_NAMES = [
    ("RANSOMWARE",  "ransomware"),
    ("TROJAN",      "trojan"),
    ("CRYPTOMINER", "cryptominer"),
]

def get_verdict(scores: dict) -> tuple:
    """Return (threat_label, confidence_label, color_code).

    When two or more threats score within TIE_DELTA of the maximum AND
    both exceed MIN_ACTIVE, all are reported as a compound label
    (e.g. 'RANSOMWARE + TROJAN') rather than silently dropping the runner-up.
    """
    TIE_DELTA = 0.05   # within 5 pp of the top score → considered tied
    MIN_ACTIVE = 0.35  # must reach 35% to appear in a compound label

    max_score = max(scores.values())

    if max_score < 0.10:
        return "BENIGN",     "SAFE",          "\033[92m"   # green
    if max_score < 0.40:
        return "SUSPICIOUS", "INCONCLUSIVE",  "\033[93m"   # yellow

    # Collect every threat that is "tied" with the leader
    active = [
        label for label, key in _THREAT_NAMES
        if scores[key] >= max_score - TIE_DELTA and scores[key] >= MIN_ACTIVE
    ]
    threat_label = " + ".join(active)

    if max_score < 0.70:
        return threat_label, "LIKELY THREAT",    "\033[33m"   # orange
    return threat_label,     "HIGH CONFIDENCE",  "\033[91m"   # red

# ══════════════════════════════════════════════════════════════════
# 7b. ASYMMETRIC EWMA FEEDBACK
# ══════════════════════════════════════════════════════════════════

class EWMAFeedback:
    """Asymmetric Exponential Weighted Moving Average — temporal feedback state.

    Scores rise fast (ALPHA_RISE=0.15): a new threat signal dominates within
    one window so alarms are not delayed.
    Scores fall slowly (ALPHA_FALL=0.85): a briefly-quiet process cannot reset
    the alarm in a single window — burst-pause evasion is neutralised.

    One instance per monitoring session; call .step() once per window.

        ewma = EWMAFeedback()
        raw, smoothed = ewma.step(run_inference(inputs))
        verdict = get_verdict(smoothed)   # verdict uses smoothed, not raw
    """
    ALPHA_RISE = 0.15   # small α → new value dominates  → fast upward response
    ALPHA_FALL = 0.85   # large α → prev value dominates → slow downward decay

    def __init__(self):
        self._state = {"ransomware": 0.0, "trojan": 0.0, "cryptominer": 0.0}

    def step(self, raw: dict) -> tuple:
        """Apply asymmetric EWMA and return (raw, smoothed) score dicts."""
        smoothed = {}
        for key in ("ransomware", "trojan", "cryptominer"):
            new  = raw[key]
            prev = self._state[key]
            alpha = self.ALPHA_RISE if new >= prev else self.ALPHA_FALL
            smoothed[key] = round(alpha * prev + (1.0 - alpha) * new, 4)
        self._state = dict(smoothed)
        return raw, smoothed

    def reset(self):
        self._state = {"ransomware": 0.0, "trojan": 0.0, "cryptominer": 0.0}

    @property
    def state(self) -> dict:
        return dict(self._state)


# ══════════════════════════════════════════════════════════════════
# 8. TERMINAL REPORT
# ══════════════════════════════════════════════════════════════════

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
MAGENTA= "\033[95m"
DIM    = "\033[2m"

def bar(value, width=30, filled="█", empty="░"):
    n = int(round(value * width))
    return filled * n + empty * (width - n)

def prob_color(p):
    if p >= 0.80: return RED
    if p >= 0.60: return "\033[33m"
    if p >= 0.40: return YELLOW
    if p >= 0.20: return GREEN
    return DIM

def print_report(inputs, scores, memberships, raw_scores=None):
    W = 72
    sep = "─" * W

    print(f"\n{BOLD}{CYAN}{'═'*W}{RESET}")
    print(f"{BOLD}{CYAN}{'FuzzyShield — Behavioral Malware Classifier':^{W}}{RESET}")
    print(f"{BOLD}{CYAN}{'Fuzzy Logic Inference Engine v2.0':^{W}}{RESET}")
    print(f"{CYAN}{'═'*W}{RESET}\n")

    # ── Input Values ──────────────────────────────────────────────
    print(f"{BOLD}■ INPUT VARIABLES{RESET}")
    print(sep)
    input_labels = {
        "cpu":    ("CPU Usage",           "%",     100),
        "mem":    ("Memory (RSS)",         "MB",   2048),
        "fwrite": ("File Write Rate",      "MB/s",  200),
        "file_read":  ("File Read Rate",       "MB/s",  200),
        "nettx":  ("Network TX",           "KB/s",10000),
        "netrx":  ("Network RX",           "KB/s",10000),
        "ext":    ("Unique Extensions",    "",       50),
        "conn":   ("Active Connections",   "",      500),
        "ent":    ("Output Entropy",       "bits/B",  8),
        "priv":   ("Priv-Esc Attempts",    "",       20),
    }
    for k, (label, unit, mx) in input_labels.items():
        v   = inputs[k]
        pct = v / mx
        b   = bar(pct, 20)
        print(f"  {label:<22} {CYAN}{v:>8.2f}{RESET} {unit:<6}  [{CYAN}{b}{RESET}]  {pct*100:4.1f}%")
    print()

    # ── Membership Degrees ────────────────────────────────────────
    print(f"{BOLD}■ FUZZY MEMBERSHIP ACTIVATIONS{RESET}")
    print(sep)
    for var_name, terms in memberships.items():
        label = input_labels[var_name][0]
        active = {k: v for k, v in terms.items() if v > 0.001}
        if not active:
            continue
        parts = []
        for term, deg in active.items():
            col = CYAN if deg > 0.5 else (YELLOW if deg > 0.2 else DIM)
            parts.append(f"{col}{term}={deg:.3f}{RESET}")
        print(f"  {label:<22}  " + "  ".join(parts))
    print()

    # ── Threat Scores ─────────────────────────────────────────────
    print(f"{BOLD}■ THREAT CLASSIFICATION SCORES{RESET}")
    print(sep)
    threats = {
        "Ransomware":  (scores["ransomware"],  "🔒", RED),
        "Trojan":      (scores["trojan"],       "🐴", YELLOW),
        "Cryptominer": (scores["cryptominer"],  "⛏",  MAGENTA),
    }
    for name, (prob, icon, col) in threats.items():
        b = bar(prob, 35)
        level = ("CRITICAL" if prob>=0.8 else "HIGH" if prob>=0.6 else
                 "MODERATE" if prob>=0.4 else "LOW"  if prob>=0.2 else
                 "TRACE"    if prob>=0.05 else "NONE")
        print(f"  {icon} {name:<14} [{col}{b}{RESET}]  {col}{prob*100:5.1f}%  {BOLD}{col}{level}{RESET}")
    print()

    # ── Temporal Feedback (EWMA) ──────────────────────────────────
    if raw_scores is not None:
        print(f"{BOLD}■ TEMPORAL FEEDBACK  (Asymmetric EWMA  α↑=0.15 · α↓=0.85){RESET}")
        print(sep)
        for name, key, col in [("Ransomware",  "ransomware",  RED),
                                ("Trojan",      "trojan",      YELLOW),
                                ("Cryptominer", "cryptominer", MAGENTA)]:
            rv   = raw_scores[key]
            sv   = scores[key]
            diff = sv - rv
            if diff > 0.005:
                arrow = f"{RED}↑ held up {RESET}"
            elif diff < -0.005:
                arrow = f"{GREEN}↓ decay  {RESET}"
            else:
                arrow = f"{DIM}→ stable {RESET}"
            print(f"  {name:<14}  raw {col}{rv*100:5.1f}%{RESET}  {arrow}"
                  f"  smoothed {col}{BOLD}{sv*100:5.1f}%{RESET}"
                  f"  {DIM}(Δ {diff*100:+.1f}%){RESET}")
        print()

    # ── Verdict ───────────────────────────────────────────────────
    threat_type, confidence, vcol = get_verdict(scores)
    print(f"{BOLD}■ VERDICT{RESET}")
    print(sep)
    print(f"  {vcol}{BOLD}  ► {confidence}: {threat_type}  {RESET}")
    max_score = max(scores.values())
    verdict_src = "smoothed" if raw_scores is not None else "raw"
    print(f"  Max threat score: {vcol}{BOLD}{max_score*100:.1f}%{RESET}"
          f"  {DIM}({verdict_src}){RESET}")
    print()

    # ── Summary advice ────────────────────────────────────────────
    _advice = {
        "BENIGN":      "No significant behavioral anomaly detected. Continue monitoring.",
        "SUSPICIOUS":  "Weak threat signals. Manual review and extended monitoring recommended.",
        "RANSOMWARE":  "Isolate process immediately. Preserve disk image. Check shadow copy deletion.",
        "TROJAN":      "Block outbound connections. Inspect DNS queries. Capture network traffic.",
        "CRYPTOMINER": "Kill process. Check cron jobs and startup persistence for CPU drain.",
    }
    # Build advice from each active component (handles compound labels like "R + T")
    components = [p.strip() for p in threat_type.split("+")]
    advice_lines = [_advice[c] for c in components if c in _advice]
    if not advice_lines:
        advice_lines = [_advice["SUSPICIOUS"]]
    if len(advice_lines) == 1:
        print(f"  Recommendation: {DIM}{advice_lines[0]}{RESET}\n")
    else:
        print(f"  Recommendations:")
        for line in advice_lines:
            print(f"    {DIM}• {line}{RESET}")
        print()
    print(f"{CYAN}{'═'*W}{RESET}\n")

# ══════════════════════════════════════════════════════════════════
# 9. FIGURE 1 — MEMBERSHIP FUNCTION PLOTS
# ══════════════════════════════════════════════════════════════════

PLOT_VARS = [
    ("cpu",    u_cpu,    cpu,    "CPU Usage (%)",          "cpu_val"),
    ("mem",    u_mem,    mem,    "Memory RSS (MB)",         "mem_val"),
    ("fwrite", u_fwrite, fwrite, "File Write Rate (MB/s)",  "fwrite_val"),
    ("file_read",  u_fread,  file_read,  "File Read Rate (MB/s)",   "fread_val"),
    ("nettx",  u_nettx,  nettx,  "Network TX (KB/s)",       "nettx_val"),
    ("netrx",  u_netrx,  netrx,  "Network RX (KB/s)",       "netrx_val"),
    ("ext",    u_ext,    ext,    "Unique Extensions",        "ext_val"),
    ("conn",   u_conn,   conn,   "Active Connections",       "conn_val"),
    ("ent",    u_ent,    ent,    "Output Entropy (bits/B)",  "ent_val"),
    ("priv",   u_priv,   priv,   "Priv-Esc Attempts",        "priv_val"),
]

TERM_COLORS = {
    "idle":"#4fc3f7",   "tiny":"#4fc3f7",   "none":"#4fc3f7",
    "single":"#4fc3f7", "silent":"#4fc3f7", "ordered":"#4fc3f7",
    "low":"#81c784",    "small":"#81c784",   "few":"#81c784",
    "moderate":"#fff176","medium":"#fff176",  "several":"#fff176",
    "high":"#ffb74d",   "large":"#ffb74d",   "many":"#ffb74d",
    "extreme":"#e57373","huge":"#e57373",    "mass":"#e57373",
    "flood":"#e57373",  "swarm":"#e57373",   "max":"#e57373",
    "critical":"#ef9a9a",
}

def plot_membership_functions(inputs, filename="fuzzy_results.png"):
    fig, axes = plt.subplots(5, 2, figsize=(16, 20))
    fig.patch.set_facecolor("#0d1117")
    axes = axes.flatten()

    for idx, (key, universe, var_obj, xlabel, _) in enumerate(PLOT_VARS):
        ax = axes[idx]
        ax.set_facecolor("#161b22")
        ax.tick_params(colors="#8b949e", labelsize=8)
        for spine in ax.spines.values():
            spine.set_edgecolor("#30363d")

        for term_name, term_obj in var_obj.terms.items():
            color = TERM_COLORS.get(term_name, "#aaaaaa")
            ax.plot(universe, term_obj.mf, label=term_name, color=color, linewidth=1.8)
            ax.fill_between(universe, term_obj.mf, alpha=0.08, color=color)

        # Draw vertical line at current input value
        val = inputs[key]
        ax.axvline(x=val, color="#00e5ff", linewidth=1.5, linestyle="--", alpha=0.9, label=f"input={val}")

        # Shade activated area for each term at current value
        for term_name, term_obj in var_obj.terms.items():
            deg = fuzz.interp_membership(universe, term_obj.mf, val)
            if deg > 0.01:
                color = TERM_COLORS.get(term_name, "#aaaaaa")
                clipped = np.fmin(term_obj.mf, deg)
                ax.fill_between(universe, 0, clipped, alpha=0.30, color=color)

        ax.set_title(xlabel, color="#e6edf3", fontsize=10, fontweight="bold", pad=6)
        ax.set_xlabel("", fontsize=8)
        ax.set_ylabel("Membership μ(x)", color="#8b949e", fontsize=8)
        ax.set_ylim(0, 1.05)
        ax.set_xlim(universe[0], universe[-1])
        ax.legend(fontsize=7, framealpha=0.2, labelcolor="#c9d1d9",
                  facecolor="#21262d", edgecolor="#30363d", ncol=3,
                  loc="upper right")
        ax.grid(axis="y", color="#21262d", linewidth=0.6)

    fig.suptitle("FuzzyShield — Membership Functions (all inputs)\nVertical dashed line = current input value  |  Shaded = activated region",
                 color="#e6edf3", fontsize=13, fontweight="bold", y=0.995)
    plt.tight_layout(rect=[0, 0, 1, 0.99])
    plt.savefig(filename, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  [✓] Saved: {filename}")

# ══════════════════════════════════════════════════════════════════
# 10. FIGURE 2 — RESULTS DASHBOARD
# ══════════════════════════════════════════════════════════════════

def plot_results_dashboard(inputs, scores, memberships, scenario_name,
                           filename="fuzzy_output.png"):
    fig = plt.figure(figsize=(18, 11))
    fig.patch.set_facecolor("#0d1117")
    gs  = GridSpec(3, 3, figure=fig, hspace=0.55, wspace=0.38,
                   left=0.06, right=0.97, top=0.92, bottom=0.07)

    # ── (A) Threat Score Bar Chart ────────────────────────────────
    ax_scores = fig.add_subplot(gs[0, :2])
    ax_scores.set_facecolor("#161b22")
    threat_names = ["Ransomware", "Trojan", "Cryptominer"]
    vals = [scores["ransomware"], scores["trojan"], scores["cryptominer"]]
    colors_bar = ["#f85149", "#e3b341", "#bc8cff"]
    bars = ax_scores.barh(threat_names, [v*100 for v in vals],
                          color=colors_bar, height=0.45, zorder=3)
    for bar_obj, v in zip(bars, vals):
        ax_scores.text(v*100 + 0.5, bar_obj.get_y() + bar_obj.get_height()/2,
                       f"{v*100:.1f}%", va="center", ha="left",
                       color="#e6edf3", fontsize=11, fontweight="bold")
    ax_scores.set_xlim(0, 110)
    ax_scores.set_xlabel("Defuzzified Probability (%)", color="#8b949e", fontsize=9)
    ax_scores.set_title("Threat Classification Scores (Centroid Defuzzification)",
                         color="#e6edf3", fontsize=10, fontweight="bold")
    ax_scores.tick_params(colors="#8b949e")
    for sp in ax_scores.spines.values(): sp.set_edgecolor("#30363d")
    ax_scores.axvline(40, color="#444", linewidth=0.8, linestyle=":")
    ax_scores.axvline(70, color="#666", linewidth=0.8, linestyle=":")
    ax_scores.text(40, -0.55, "40%", color="#555", fontsize=7, ha="center")
    ax_scores.text(70, -0.55, "70%", color="#666", fontsize=7, ha="center")
    ax_scores.grid(axis="x", color="#21262d", linewidth=0.7, zorder=0)

    # ── (B) Radar Chart ───────────────────────────────────────────
    ax_radar = fig.add_subplot(gs[0, 2], polar=True)
    ax_radar.set_facecolor("#161b22")
    categories = ["Ransomware", "Trojan", "Cryptominer"]
    N = len(categories)
    angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()
    angles += angles[:1]
    radar_vals = [scores["ransomware"], scores["trojan"], scores["cryptominer"]]
    radar_vals += radar_vals[:1]
    ax_radar.plot(angles, radar_vals, "o-", color="#00e5ff", linewidth=2)
    ax_radar.fill(angles, radar_vals, alpha=0.20, color="#00e5ff")
    ax_radar.set_xticks(angles[:-1])
    ax_radar.set_xticklabels(categories, color="#c9d1d9", fontsize=8)
    ax_radar.set_ylim(0, 1)
    ax_radar.set_yticks([0.25, 0.5, 0.75, 1.0])
    ax_radar.set_yticklabels(["25%","50%","75%","100%"], color="#555", fontsize=6)
    ax_radar.grid(color="#30363d", linewidth=0.7)
    ax_radar.spines["polar"].set_edgecolor("#30363d")
    ax_radar.set_title("Threat Radar", color="#e6edf3", fontsize=9, pad=12)

    # ── (C) Input Membership Heatmap ─────────────────────────────
    ax_heat = fig.add_subplot(gs[1, :2])
    ax_heat.set_facecolor("#161b22")

    var_labels = ["CPU","MEM","F-WR","F-RD","NET-TX","NET-RX","EXT","CONN","ENT","PRIV"]
    term_labels = ["none/idle/ordered/single/silent/tiny",
                   "low/small/few",
                   "moderate/medium/several",
                   "high/large/many",
                   "extreme/huge/mass/flood/swarm/max"]
    term_short  = ["very low", "low", "medium", "high", "very high"]

    heat_matrix = np.zeros((len(var_labels), 5))
    var_keys = ["cpu","mem","fwrite","file_read","nettx","netrx","ext","conn","ent","priv"]
    for vi, vk in enumerate(var_keys):
        sorted_terms = list(memberships[vk].items())
        for ti, (_, deg) in enumerate(sorted_terms):
            if ti < 5:
                heat_matrix[vi, ti] = deg

    im = ax_heat.imshow(heat_matrix.T, aspect="auto", cmap="YlOrRd",
                         vmin=0, vmax=1, origin="lower")
    ax_heat.set_xticks(range(len(var_labels)))
    ax_heat.set_xticklabels(var_labels, color="#c9d1d9", fontsize=8)
    ax_heat.set_yticks(range(5))
    ax_heat.set_yticklabels(term_short, color="#c9d1d9", fontsize=8)
    ax_heat.set_title("Input Membership Degree Heatmap",
                       color="#e6edf3", fontsize=10, fontweight="bold")
    for (vi, ti), val in np.ndenumerate(heat_matrix):
        if val > 0.05:
            ax_heat.text(vi, ti, f"{val:.2f}", ha="center", va="center",
                         fontsize=7, color="black" if val > 0.5 else "white")
    cb = fig.colorbar(im, ax=ax_heat, fraction=0.03, pad=0.02)
    cb.ax.tick_params(colors="#8b949e", labelsize=7)
    cb.set_label("μ(x)", color="#8b949e", fontsize=8)

    # ── (D) Output MF + Centroid ──────────────────────────────────
    threat_plot = [
        ("ransomware",  "#f85149", gs[2, 0]),
        ("trojan",      "#e3b341", gs[2, 1]),
        ("cryptominer", "#bc8cff", gs[2, 2]),
    ]
    out_var_map = {"ransomware": ransomware, "trojan": trojan, "cryptominer": cryptominer}

    for tname, tcol, gspec in threat_plot:
        ax = fig.add_subplot(gspec)
        ax.set_facecolor("#161b22")
        out_var = out_var_map[tname]
        for tterm, tobj in out_var.terms.items():
            ax.plot(u_out, tobj.mf, color=tcol, linewidth=1.5, alpha=0.6)
            ax.fill_between(u_out, tobj.mf, alpha=0.05, color=tcol)
        # Centroid line
        cv = scores[tname]
        ax.axvline(cv, color=tcol, linewidth=2.5, linestyle="--")
        ax.text(cv, 1.02, f"{cv*100:.1f}%", ha="center", color=tcol,
                fontsize=9, fontweight="bold",
                transform=ax.get_xaxis_transform())
        ax.set_title(f"{tname.capitalize()} Output MF",
                     color="#e6edf3", fontsize=9, fontweight="bold")
        ax.set_xlabel("Probability", color="#8b949e", fontsize=8)
        ax.set_ylim(0, 1.1)
        ax.set_xlim(0, 1)
        ax.tick_params(colors="#8b949e", labelsize=7)
        for sp in ax.spines.values(): sp.set_edgecolor("#30363d")
        ax.grid(color="#21262d", linewidth=0.5)

    # ── (E) Input summary table ───────────────────────────────────
    ax_tbl = fig.add_subplot(gs[1, 2])
    ax_tbl.set_facecolor("#161b22")
    ax_tbl.axis("off")
    input_labels_short = {
        "cpu":"CPU (%)", "mem":"Mem (MB)", "fwrite":"FWrite MB/s",
        "file_read":"FRead MB/s", "nettx":"TX KB/s", "netrx":"RX KB/s",
        "ext":"Uniq Ext", "conn":"Conn", "ent":"Entropy", "priv":"PrivEsc"
    }
    rows = [[lbl, f"{inputs[k]:.2f}"] for k, lbl in input_labels_short.items()]
    tbl = ax_tbl.table(cellText=rows, colLabels=["Variable","Value"],
                       loc="center", cellLoc="left")
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(8)
    for (r, c), cell in tbl.get_celld().items():
        cell.set_facecolor("#21262d" if r % 2 == 0 else "#161b22")
        cell.set_text_props(color="#c9d1d9")
        cell.set_edgecolor("#30363d")
    ax_tbl.set_title("Input Summary", color="#e6edf3", fontsize=9, pad=6)

    # ── Super title ───────────────────────────────────────────────
    threat_type, confidence, _ = get_verdict(scores)
    fig.suptitle(
        f"FuzzyShield Results — Scenario: {scenario_name.upper()}  │  "
        f"Verdict: {confidence} → {threat_type}",
        color="#e6edf3", fontsize=13, fontweight="bold"
    )

    plt.savefig(filename, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  [✓] Saved: {filename}")

# ══════════════════════════════════════════════════════════════════
# 10b. 3D RULE SURFACE PLOTS
# ══════════════════════════════════════════════════════════════════

def plot_3d_surfaces(filename="fuzzy_3d_surfaces.png"):
    """Generate 6 rule-surface plots identical in scope to the MATLAB version."""
    from mpl_toolkits.mplot3d import Axes3D  # noqa: F401 — registers '3d' projection

    # Default benign background for non-varied inputs
    defaults = dict(cpu=12, mem=180, fwrite=4, file_read=8,
                    nettx=60, netrx=90, ext=3, conn=4, ent=2.1, priv=0)

    surface_defs = [
        ("ransomware",  "fwrite", u_fwrite, "ent",  u_ent,   "hot",
         "Ransomware  |  fwrite vs entropy",   "fwrite (MB/s)",  "entropy (bits/B)"),
        ("ransomware",  "fwrite", u_fwrite, "ext",  u_ext,   "hot",
         "Ransomware  |  fwrite vs ext",       "fwrite (MB/s)",  "unique extensions"),
        ("trojan",      "nettx",  u_nettx,  "conn", u_conn,  "plasma",
         "Trojan  |  nettx vs connections",    "nettx (KB/s)",   "connections"),
        ("trojan",      "nettx",  u_nettx,  "priv", u_priv,  "plasma",
         "Trojan  |  nettx vs priv-esc",       "nettx (KB/s)",   "priv-esc attempts"),
        ("cryptominer", "cpu",    u_cpu,    "nettx",u_nettx, "cool",
         "Cryptominer  |  cpu vs nettx",       "cpu (%)",        "nettx (KB/s)"),
        ("cryptominer", "cpu",    u_cpu,    "mem",  u_mem,   "cool",
         "Cryptominer  |  cpu vs memory",      "cpu (%)",        "memory (MB)"),
    ]

    N = 12  # grid resolution per axis
    print("  Generating 3D surfaces …", end="", flush=True)

    fig = plt.figure(figsize=(18, 12))
    fig.patch.set_facecolor("#0d1117")

    for idx, (out_key, k1, u1, k2, u2, cmap, title, xlabel, ylabel) in enumerate(surface_defs):
        surf_sim  = ctrl.ControlSystemSimulation(system)
        valid_kys = {a.label for a in surf_sim.ctrl.antecedents}

        x_vals = np.linspace(u1[0],  u1[-1],  N)
        y_vals = np.linspace(u2[0],  u2[-1],  N)
        X, Y   = np.meshgrid(x_vals, y_vals)
        Z      = np.zeros_like(X)

        for i in range(N):
            for j in range(N):
                inp = dict(defaults)
                inp[k1] = float(X[i, j])
                inp[k2] = float(Y[i, j])
                for key, val in inp.items():
                    if key in valid_kys:
                        surf_sim.input[key] = float(val)
                try:
                    surf_sim.compute()
                    Z[i, j] = surf_sim.output.get(out_key, 0.0)
                except Exception:
                    Z[i, j] = 0.0

        ax = fig.add_subplot(2, 3, idx + 1, projection='3d')
        ax.set_facecolor("#0d1117")
        surf = ax.plot_surface(X, Y, Z, cmap=cmap, alpha=0.90,
                               edgecolor='none', antialiased=True)
        ax.set_zlim(0, 1)
        ax.set_xlabel(xlabel,      color="#8b949e", fontsize=7, labelpad=3)
        ax.set_ylabel(ylabel,      color="#8b949e", fontsize=7, labelpad=3)
        ax.set_zlabel("Probability", color="#8b949e", fontsize=7, labelpad=3)
        ax.set_title(title,        color="#e6edf3", fontsize=8, fontweight="bold", pad=4)
        ax.tick_params(colors="#8b949e", labelsize=6)
        for pane in (ax.xaxis.pane, ax.yaxis.pane, ax.zaxis.pane):
            pane.fill = False
            pane.set_edgecolor("#21262d")
        fig.colorbar(surf, ax=ax, shrink=0.42, pad=0.06).ax.tick_params(
            labelsize=6, colors="#8b949e")
        ax.view_init(elev=28, azim=-42)
        print(".", end="", flush=True)

    print()
    fig.suptitle(
        "FuzzyShield — 3D Rule Surface Plots"
        "  (Mamdani Inference · Centroid Defuzzification)",
        color="#e6edf3", fontsize=12, fontweight="bold")
    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  [✓] Saved: {filename}")


# ══════════════════════════════════════════════════════════════════
# 10c. TIME-SERIES PLOT  (PID monitoring)
# ══════════════════════════════════════════════════════════════════

def plot_timeseries(history: list, pid: int, proc_name: str,
                   filename: str = "fuzzy_timeseries.png"):
    """Plot threat score and key metric evolution across PID monitoring checks."""
    if len(history) < 2:
        return

    checks  = [h["check"]  for h in history]
    # smoothed scores (from EWMA) are stored in "scores"
    r_vals  = [h["scores"]["ransomware"]  * 100 for h in history]
    t_vals  = [h["scores"]["trojan"]      * 100 for h in history]
    c_vals  = [h["scores"]["cryptominer"] * 100 for h in history]

    # raw FIS scores available when EWMA feedback is active
    has_ewma = all("raw_scores" in h for h in history)
    if has_ewma:
        r_raw = [h["raw_scores"]["ransomware"]  * 100 for h in history]
        t_raw = [h["raw_scores"]["trojan"]      * 100 for h in history]
        c_raw = [h["raw_scores"]["cryptominer"] * 100 for h in history]

    cpu_n   = [h["inputs"]["cpu"]    / 100  * 100 for h in history]
    fw_n    = [h["inputs"]["fwrite"] / 200  * 100 for h in history]
    conn_n  = [h["inputs"]["conn"]   / 500  * 100 for h in history]
    ent_n   = [h["inputs"]["ent"]    / 8    * 100 for h in history]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), sharex=True)
    fig.patch.set_facecolor("#0d1117")

    # ── Threat scores ──────────────────────────────────────────────
    ax1.set_facecolor("#161b22")

    # Raw FIS scores — thin dashed (only when EWMA is active)
    if has_ewma:
        ax1.plot(checks, r_raw, "--", color="#f85149", lw=1.0, alpha=0.45, label="Ransomware (raw)")
        ax1.plot(checks, t_raw, "--", color="#e3b341", lw=1.0, alpha=0.45, label="Trojan (raw)")
        ax1.plot(checks, c_raw, "--", color="#bc8cff", lw=1.0, alpha=0.45, label="Cryptominer (raw)")

    # Smoothed EWMA scores — solid bold
    smooth_label = " (EWMA)" if has_ewma else ""
    ax1.plot(checks, r_vals, "o-", color="#f85149", lw=2.2, ms=5, label=f"Ransomware{smooth_label}")
    ax1.plot(checks, t_vals, "s-", color="#e3b341", lw=2.2, ms=5, label=f"Trojan{smooth_label}")
    ax1.plot(checks, c_vals, "^-", color="#bc8cff", lw=2.2, ms=5, label=f"Cryptominer{smooth_label}")
    ax1.fill_between(checks, r_vals, alpha=0.12, color="#f85149")
    ax1.fill_between(checks, t_vals, alpha=0.12, color="#e3b341")
    ax1.fill_between(checks, c_vals, alpha=0.12, color="#bc8cff")
    ax1.axhline(40, color="#444", lw=0.8, ls=":", label="40% (Likely Threat)")
    ax1.axhline(70, color="#666", lw=0.8, ls=":", label="70% (High Confidence)")
    ax1.set_ylim(0, 108)
    ax1.set_ylabel("Threat Probability (%)", color="#8b949e", fontsize=9)
    feedback_note = "  ·  EWMA feedback active  (α↑=0.15 · α↓=0.85)" if has_ewma else ""
    ax1.set_title(
        f"FuzzyShield — Real-Time Threat Score Evolution\n"
        f"PID {pid}  ({proc_name})  ·  {len(checks)} checks{feedback_note}",
        color="#e6edf3", fontsize=11, fontweight="bold")
    ax1.legend(loc="upper right", facecolor="#21262d",
               labelcolor="#c9d1d9", edgecolor="#30363d", fontsize=8)
    ax1.tick_params(colors="#8b949e", labelsize=8)
    ax1.grid(color="#21262d", lw=0.6)
    for sp in ax1.spines.values(): sp.set_edgecolor("#30363d")

    # ── Key metrics (normalised) ───────────────────────────────────
    ax2.set_facecolor("#161b22")
    ax2.plot(checks, cpu_n,  "--", color="#4fc3f7", lw=1.8, label="CPU  (% of max)")
    ax2.plot(checks, fw_n,   "--", color="#81c784", lw=1.8, label="fwrite  (% of max)")
    ax2.plot(checks, conn_n, "--", color="#ffb74d", lw=1.8, label="Connections  (% of max)")
    ax2.plot(checks, ent_n,  "--", color="#ef9a9a", lw=1.8, label="Entropy  (% of max)")
    ax2.set_ylim(0, 108)
    ax2.set_xlabel("Check Number", color="#8b949e", fontsize=9)
    ax2.set_ylabel("Normalised Value (%)", color="#8b949e", fontsize=9)
    ax2.set_title("Key Behavioural Metrics Over Time",
                  color="#e6edf3", fontsize=10, fontweight="bold")
    ax2.legend(loc="upper right", facecolor="#21262d",
               labelcolor="#c9d1d9", edgecolor="#30363d", fontsize=8)
    ax2.tick_params(colors="#8b949e", labelsize=8)
    ax2.grid(color="#21262d", lw=0.6)
    for sp in ax2.spines.values(): sp.set_edgecolor("#30363d")

    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close()
    print(f"  [✓] Saved: {filename}")


# ══════════════════════════════════════════════════════════════════
# 11. PID MONITORING
# ══════════════════════════════════════════════════════════════════

def _shannon_entropy(data: bytes) -> float:
    if len(data) < 2:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

def _entropy_from_pid(pid: int) -> float:
    """Estimate output entropy by sampling the tail of open writable files."""
    sample = b""
    try:
        proc = psutil.Process(pid)
        for f in proc.open_files():
            if not os.access(f.path, os.R_OK):
                continue
            try:
                with open(f.path, "rb") as fh:
                    fh.seek(0, 2)
                    size = fh.tell()
                    if size < 64:
                        continue
                    fh.seek(max(0, size - 4096))
                    sample += fh.read(4096)
                    if len(sample) >= 8192:
                        break
            except Exception:
                continue
        if len(sample) >= 64:
            return min(_shannon_entropy(sample), 8.0)
    except Exception:
        pass
    # Fallback: sample first anonymous readable memory region
    try:
        with open(f"/proc/{pid}/maps") as mf:
            for line in mf:
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith('r') and (len(parts) < 6 or parts[5] == ''):
                    start = int(parts[0].split('-')[0], 16)
                    with open(f"/proc/{pid}/mem", "rb") as mem:
                        mem.seek(start)
                        data = mem.read(4096)
                        if data:
                            return min(_shannon_entropy(data), 8.0)
    except Exception:
        pass
    return 3.5  # mid-range default when nothing is readable

def _priv_score_from_pid(pid: int) -> float:
    """Estimate privilege level from effective Linux capabilities."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    cap_eff = int(line.split()[1], 16)
                    return min(bin(cap_eff).count('1') * 1.5, 20.0)
    except Exception:
        pass
    return 0.0

def collect_pid_metrics(pid: int, interval: float) -> dict:
    """Sample /proc and psutil over `interval` seconds, return input dict."""
    if not _PSUTIL:
        raise RuntimeError("psutil not installed — run: env-fuzzy/bin/pip install psutil")

    proc = psutil.Process(pid)
    proc.cpu_percent(interval=None)          # warm-up (first call returns 0)
    io1  = proc.io_counters()
    net1 = psutil.net_io_counters()

    time.sleep(interval)

    cpu  = min(proc.cpu_percent(interval=None), 100.0)
    io2  = proc.io_counters()
    net2 = psutil.net_io_counters()
    mem  = proc.memory_info().rss / 1024 / 1024   # MB

    dt = max(interval, 0.1)

    # write_chars / read_chars (Linux /proc/pid/io wchar/rchar) count all write() syscall bytes
    # including page-cached writes — more accurate than write_bytes (which waits for flush to disk)
    _w1 = getattr(io1, 'write_chars', None) or io1.write_bytes
    _w2 = getattr(io2, 'write_chars', None) or io2.write_bytes
    _r1 = getattr(io1, 'read_chars',  None) or io1.read_bytes
    _r2 = getattr(io2, 'read_chars',  None) or io2.read_bytes
    fwrite = max((_w2 - _w1) / 1024 / 1024 / dt, 0.0)
    fread  = max((_r2 - _r1) / 1024 / 1024 / dt, 0.0)
    nettx  = max((net2.bytes_sent - net1.bytes_sent) / 1024 / dt, 0.0)
    netrx  = max((net2.bytes_recv - net1.bytes_recv) / 1024 / dt, 0.0)

    try:
        _get_conn = getattr(proc, 'net_connections', None) or proc.connections
        conn_count = len(_get_conn(kind='all'))
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        conn_count = 0

    # Sample open_files() a few times to catch quickly-opened/closed files
    ext_set: set = set()
    for _ in range(3):
        try:
            for f in proc.open_files():
                ext = os.path.splitext(f.path)[1].lower()
                if ext:
                    ext_set.add(ext)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            break
        time.sleep(0.05)
    ext_count = len(ext_set)

    ent  = _entropy_from_pid(pid)
    priv = _priv_score_from_pid(pid)

    return dict(
        cpu       = min(cpu,        100.0),
        mem       = min(mem,       2048.0),
        fwrite    = min(fwrite,     200.0),
        file_read = min(fread,      200.0),
        nettx     = min(nettx,    10000.0),
        netrx     = min(netrx,    10000.0),
        ext       = min(ext_count,   50.0),
        conn      = min(conn_count,  500.0),
        ent       = min(ent,          8.0),
        priv      = min(priv,        20.0),
    )

def monitor_pid(pid: int, interval: float, max_checks: int):
    """Periodically collect metrics from a running PID and run fuzzy inference."""
    if not _PSUTIL:
        print(f"{RED}psutil not installed. Run: env-fuzzy/bin/pip install psutil{RESET}")
        return

    try:
        proc      = psutil.Process(pid)
        proc_name = proc.name()
    except psutil.NoSuchProcess:
        print(f"{RED}PID {pid} does not exist.{RESET}")
        return

    print(f"\n{BOLD}{CYAN}{'═'*72}{RESET}")
    print(f"{BOLD}{CYAN}  FuzzyShield — PID Monitor{RESET}")
    print(f"  Process : {BOLD}{proc_name}{RESET}  (PID {pid})")
    print(f"  Interval: {interval}s   |   "
          f"Max checks: {'∞' if max_checks == 0 else max_checks}")
    print(f"  Feedback: {BOLD}Asymmetric EWMA  (α↑=0.15 · α↓=0.85){RESET}")
    print(f"  {DIM}Network TX/RX values are system-wide (per-process bandwidth requires root){RESET}")
    print(f"{BOLD}{CYAN}{'═'*72}{RESET}")
    print(f"  Press {BOLD}Ctrl+C{RESET} to stop.\n")

    session_ts  = _ts()
    session_dir = _pid_session_dir(pid, proc_name, session_ts)
    check_num   = 0
    history     = []   # [{check, ts, inputs, scores, raw_scores}]
    ewma        = EWMAFeedback()

    print(f"  {DIM}Session output → {os.path.relpath(session_dir, _PROJECT_ROOT)}{RESET}")

    try:
        while max_checks == 0 or check_num < max_checks:
            check_num += 1
            ts = time.strftime("%H:%M:%S")

            print(f"\n{DIM}[{ts}] ── Check #{check_num} — collecting {interval}s window ──{RESET}")

            try:
                proc = psutil.Process(pid)
                if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                    print(f"{RED}Process {pid} has terminated.{RESET}")
                    break
            except psutil.NoSuchProcess:
                print(f"{RED}Process {pid} no longer exists.{RESET}")
                break

            try:
                inputs = collect_pid_metrics(pid, interval)
            except Exception as e:
                print(f"{RED}Metric collection error: {e}{RESET}")
                continue

            raw_scores, scores = ewma.step(run_inference(inputs))
            memberships = get_memberships(inputs)
            history.append(dict(check=check_num, ts=ts, inputs=inputs,
                                scores=scores, raw_scores=raw_scores))

            print_report(inputs, scores, memberships, raw_scores)

            # Each check gets its own timestamped files inside the session folder
            check_tag = f"check{check_num:02d}"
            mf_file  = os.path.join(session_dir, f"{check_tag}_membership.png")
            res_file = os.path.join(session_dir, f"{check_tag}_results.png")
            ts_file  = os.path.join(session_dir, "timeseries.png")

            plot_membership_functions(inputs, mf_file)
            plot_results_dashboard(
                inputs, scores, memberships,
                f"PID {pid} ({proc_name}) — check #{check_num} @ {ts}",
                res_file
            )
            if len(history) >= 2:
                plot_timeseries(history, pid, proc_name, ts_file)

            threat_type, confidence, vcol = get_verdict(scores)
            max_score = max(scores.values())
            print(f"\n  {vcol}{BOLD}[{ts}] PID {pid} ({proc_name})"
                  f"  →  {confidence}: {threat_type}"
                  f"  ({max_score*100:.1f}%){RESET}")

            if max_checks == 0 or check_num < max_checks:
                print(f"  {DIM}Next check in {interval}s … (Ctrl+C to stop){RESET}")

    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Monitoring stopped.{RESET}\n")

    # Final time-series save
    ts_file = os.path.join(session_dir, "timeseries.png")
    if len(history) >= 2:
        plot_timeseries(history, pid, proc_name, ts_file)
    print(f"\n  {DIM}Session saved to: {os.path.relpath(session_dir, _PROJECT_ROOT)}{RESET}")

# ══════════════════════════════════════════════════════════════════
# 12. INTERACTIVE INPUT
# ══════════════════════════════════════════════════════════════════

def interactive_input() -> dict:
    print(f"\n{BOLD}{CYAN}FuzzyShield — Manual Input Mode{RESET}")
    print("Enter values for each behavioral metric (press Enter for default):\n")
    fields = [
        ("cpu",    "CPU Usage",           "%",      0, 100,   50.0),
        ("mem",    "Memory RSS",           "MB",     0, 2048, 200.0),
        ("fwrite", "File Write Rate",      "MB/s",   0, 200,   10.0),
        ("file_read",  "File Read Rate",       "MB/s",   0, 200,    5.0),
        ("nettx",  "Network TX",           "KB/s",   0,10000,  50.0),
        ("netrx",  "Network RX",           "KB/s",   0,10000, 100.0),
        ("ext",    "Unique Extensions",    "",       0,  50,    3.0),
        ("conn",   "Active Connections",   "",       0, 500,    5.0),
        ("ent",    "Output Entropy",       "bits/B", 0,   8,   3.5),
        ("priv",   "Priv-Esc Attempts",    "",       0,  20,    0.0),
    ]
    result = {}
    for key, label, unit, lo, hi, default in fields:
        prompt = f"  {label:<22} [{lo}–{hi} {unit}] (default {default}): "
        raw = input(prompt).strip()
        if raw == "":
            result[key] = default
        else:
            try:
                v = float(raw)
                result[key] = max(lo, min(hi, v))
            except ValueError:
                print(f"  Invalid input, using default {default}")
                result[key] = default
    return result

# ══════════════════════════════════════════════════════════════════
# 13. STARTUP MENU
# ══════════════════════════════════════════════════════════════════

def _choose_mode() -> tuple:
    """Ask the user how they want to provide input. Returns (mode, kwargs)."""
    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║   FuzzyShield — Behavioral Malware Classifier ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════╝{RESET}\n")
    print("  How would you like to proceed?\n")
    print(f"  {BOLD}[1]{RESET}  PID monitor   — analyse a running process in real-time")
    print(f"  {BOLD}[2]{RESET}  Manual input  — enter metric values by hand")
    print(f"  {BOLD}[3]{RESET}  Preset scenario — ransomware / trojan / cryptominer / benign / mixed\n")

    while True:
        raw = input("  Choice [1/2/3]: ").strip()
        if raw in ("1", "2", "3"):
            break
        print(f"  {RED}Please enter 1, 2, or 3.{RESET}")

    if raw == "1":
        while True:
            pid_raw = input("\n  PID to monitor: ").strip()
            try:
                pid = int(pid_raw)
                break
            except ValueError:
                print(f"  {RED}Invalid PID.{RESET}")

        iv_raw = input("  Check interval in seconds [default 5]: ").strip()
        interval = float(iv_raw) if iv_raw else 5.0

        mc_raw = input("  Number of checks [default 0 = unlimited]: ").strip()
        max_checks = int(mc_raw) if mc_raw else 0

        return "pid", dict(pid=pid, interval=interval, max_checks=max_checks)

    if raw == "2":
        return "manual", {}

    # raw == "3"
    preset_list = ", ".join(SCENARIOS.keys())
    print(f"\n  Available scenarios: {CYAN}{preset_list}{RESET}")
    sc = input("  Scenario name: ").strip().lower()
    if sc not in SCENARIOS:
        print(f"  {RED}Unknown scenario — defaulting to 'ransomware'.{RESET}")
        sc = "ransomware"
    return "preset", dict(scenario=sc)

# ══════════════════════════════════════════════════════════════════
# 14. SCENARIO COMPARISON TABLE
# ══════════════════════════════════════════════════════════════════

def print_comparison_table(all_results: list):
    """Print a summary comparison table for multiple scenario runs."""
    W   = 76
    col = {"ransomware": RED, "trojan": YELLOW, "cryptominer": MAGENTA,
           "suspicious": "\033[33m", "benign": GREEN}

    print(f"\n{BOLD}{CYAN}{'═'*W}{RESET}")
    print(f"{BOLD}{CYAN}{'FuzzyShield — Scenario Comparison Summary':^{W}}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*W}{RESET}")
    header = f"  {'Scenario':<14} {'Ransomware':>12} {'Trojan':>10} {'Cryptominer':>13}  {'Verdict'}"
    print(f"{BOLD}{header}{RESET}")
    print(f"  {'─'*14} {'─'*12} {'─'*10} {'─'*13}  {'─'*20}")

    for row in all_results:
        sc   = row["scenario"]
        r, t, c = row["scores"]["ransomware"], row["scores"]["trojan"], row["scores"]["cryptominer"]
        threat_type, confidence, vcol = get_verdict(row["scores"])
        r_str = f"{r*100:6.1f}%"
        t_str = f"{t*100:6.1f}%"
        c_str = f"{c*100:6.1f}%"
        mx    = max(r, t, c)
        r_col = RED    if r == mx and mx >= 0.1 else ""
        t_col = YELLOW if t == mx and mx >= 0.1 else ""
        c_col = MAGENTA if c == mx and mx >= 0.1 else ""
        stars = "▶▶▶" if mx >= 0.70 else ("▶▶ " if mx >= 0.40 else "   ")
        print(f"  {sc:<14} "
              f"{r_col}{r_str}{RESET}{'***' if r==mx and mx>=0.7 else '   ':3}  "
              f"{t_col}{t_str}{RESET}{'***' if t==mx and mx>=0.7 else '   ':3}  "
              f"{c_col}{c_str}{RESET}{'***' if c==mx and mx>=0.7 else '   ':3}  "
              f"{vcol}{BOLD}{stars} {confidence}: {threat_type}{RESET}")

    print(f"  {'─'*74}")
    print(f"  {DIM}*** = dominant threat at ≥ 70% confidence{RESET}")
    print(f"{CYAN}{'═'*W}{RESET}\n")


# ══════════════════════════════════════════════════════════════════
# 15. MAIN
# ══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="FuzzyShield — Behavioral Malware Classifier"
    )
    parser.add_argument("--scenario", "-s",
        choices=list(SCENARIOS.keys()) + ["custom"],
        default=None,
        help="Preset behavioral scenario")
    parser.add_argument("--all", "-a",
        action="store_true",
        help="Run all preset scenarios + comparison table")
    parser.add_argument("--report", "-r",
        action="store_true",
        help="Generate full report: all scenarios + 3D surfaces + comparison table")
    parser.add_argument("--pid", "-p",
        type=int, default=None,
        help="Monitor a running process by PID")
    parser.add_argument("--interval", "-i",
        type=float, default=5.0,
        help="PID monitoring interval in seconds (default: 5)")
    parser.add_argument("--checks", "-c",
        type=int, default=0,
        help="Number of PID checks, 0 = infinite (default: 0)")
    args = parser.parse_args()

    # ── Command-line PID mode ─────────────────────────────────────
    if args.pid is not None:
        monitor_pid(args.pid, args.interval, args.checks)
        return

    # ── No flags → interactive startup menu ───────────────────────
    if not args.all and not args.report and args.scenario is None:
        mode, kwargs = _choose_mode()
        if mode == "pid":
            monitor_pid(kwargs["pid"], kwargs["interval"], kwargs["max_checks"])
            return
        if mode == "manual":
            args.scenario = "custom"
        else:
            args.scenario = kwargs["scenario"]

    # ── Determine run list ────────────────────────────────────────
    run_all    = args.all or args.report
    run_list   = list(SCENARIOS.keys()) if run_all else [args.scenario or "custom"]
    all_results = []

    for scenario_name in run_list:
        print(f"\n{'═'*72}")
        print(f"  Scenario: {BOLD}{scenario_name.upper()}{RESET}")
        print(f"{'═'*72}")

        if scenario_name == "custom":
            inputs = interactive_input()
        else:
            entry = SCENARIOS[scenario_name]
            inputs = entry() if callable(entry) else entry
            label = "randomised" if callable(entry) else "preset"
            print(f"\n  Loaded {label}: {CYAN}{scenario_name}{RESET}")

        print(f"\n  {DIM}Running fuzzy inference...{RESET}")
        scores      = run_inference(inputs)
        memberships = get_memberships(inputs)

        print_report(inputs, scores, memberships)
        all_results.append(dict(scenario=scenario_name, inputs=inputs, scores=scores))

        print(f"  Generating plots...")
        mf_path  = _scenario_path(scenario_name, "membership")
        res_path = _scenario_path(scenario_name, "results")
        plot_membership_functions(inputs, mf_path)
        plot_results_dashboard(inputs, scores, memberships, scenario_name, res_path)

    # ── Post-run extras ───────────────────────────────────────────
    if len(all_results) > 1:
        print_comparison_table(all_results)

    if args.report:
        print(f"\n  {DIM}Generating 3D rule surface plots (may take ~30s)…{RESET}")
        surf_path = _analysis_path("3d_surfaces")
        plot_3d_surfaces(surf_path)

    out_rel = os.path.relpath(_OUT_ROOT, _PROJECT_ROOT)
    print(f"\n{GREEN}Done.{RESET}  Results saved to  {BOLD}{out_rel}/{RESET}\n")
    if args.report:
        print(f"  output/scenarios/       — membership + results plots per scenario")
        print(f"  output/analysis/        — 3D rule surface plots\n")


if __name__ == "__main__":
    main()
