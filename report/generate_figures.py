#!/usr/bin/env python3
"""
Generate all report figures for FuzzyShield.
Run with the project virtual environment from the report/ directory:
    ../env-fuzzy/bin/python generate_figures.py
"""

import sys, os, warnings
warnings.filterwarnings('ignore')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

FIGURES = 'figures'
os.makedirs(FIGURES, exist_ok=True)

# ── Palette ──────────────────────────────────────────────────────────────────
BG       = '#0c0e12'
PANEL    = '#141820'
GRID     = '#1c2230'
TEXT     = '#dde3ec'
DIM      = '#7a8ba0'
ACCENT_R = '#ee4444'
ACCENT_T = '#ddaa30'
ACCENT_C = '#b87cf8'
ACCENT_M = '#40d0f0'
ACCENT_G = '#44cc77'

MF_CLR = {
    'ordered':'#3ac8ff','idle':'#3ac8ff','tiny':'#3ac8ff',
    'none':'#3ac8ff','single':'#3ac8ff','silent':'#3ac8ff',
    'low':'#72c464','small':'#72c464','few':'#72c464',
    'moderate':'#f0df50','medium':'#f0df50','several':'#f0df50',
    'high':'#ff9a30','large':'#ff9a30','many':'#ff9a30',
    'extreme':'#e83535','huge':'#e83535','mass':'#e83535',
    'flood':'#e83535','swarm':'#e83535','max':'#e83535',
}

def _ax(ax):
    ax.set_facecolor(PANEL)
    ax.tick_params(colors=DIM, labelsize=8)
    for sp in ax.spines.values():
        sp.set_edgecolor(GRID)
    ax.grid(True, color=GRID, linewidth=0.5, alpha=0.8)
    return ax

def trapmf(x, a, b, c, d):
    rise = np.clip((x - a) / (b - a + 1e-12), 0, 1)
    fall = np.clip((d - x) / (d - c + 1e-12), 0, 1)
    return np.minimum(rise, fall)

def trimf(x, a, b, c):
    rise = np.clip((x - a) / (b - a + 1e-12), 0, 1)
    fall = np.clip((c - x) / (c - b + 1e-12), 0, 1)
    return np.minimum(rise, fall)

def evalmf(x, mf_type, params):
    if mf_type == 'trapmf':
        return trapmf(x, *params)
    return trimf(x, *params)

# ── Input variable definitions ────────────────────────────────────────────────
INPUTS = {
    'cpu':       ('CPU Usage (%)',               0,   100, [
        ('idle',    'trapmf',[0,0,10,20]),
        ('low',     'trapmf',[10,20,30,45]),
        ('moderate','trimf', [35,50,65]),
        ('high',    'trapmf',[55,70,80,90]),
        ('extreme', 'trapmf',[82,92,100,100]),
    ]),
    'mem':       ('Memory RSS (MB)',             0,  2048, [
        ('tiny',   'trapmf',[0,0,64,150]),
        ('small',  'trapmf',[100,180,280,400]),
        ('medium', 'trimf', [300,512,800]),
        ('large',  'trapmf',[700,900,1200,1500]),
        ('huge',   'trapmf',[1300,1600,2048,2048]),
    ]),
    'fwrite':    ('File Write Rate (MB/s)',      0,   200, [
        ('none',    'trapmf',[0,0,2,6]),
        ('low',     'trapmf',[3,10,20,35]),
        ('moderate','trimf', [25,50,80]),
        ('high',    'trapmf',[65,100,140,170]),
        ('extreme', 'trapmf',[150,175,200,200]),
    ]),
    'file_read': ('File Read Rate (MB/s)',       0,   200, [
        ('none',    'trapmf',[0,0,3,8]),
        ('low',     'trapmf',[5,15,30,50]),
        ('moderate','trimf', [35,60,95]),
        ('high',    'trapmf',[80,110,150,175]),
        ('extreme', 'trapmf',[160,180,200,200]),
    ]),
    'nettx':     ('Network TX (KB/s)',           0, 10000, [
        ('silent',  'trapmf',[0,0,10,40]),
        ('low',     'trapmf',[20,80,200,400]),
        ('moderate','trimf', [300,700,1400]),
        ('high',    'trapmf',[1000,2000,4000,6000]),
        ('flood',   'trapmf',[4500,7000,10000,10000]),
    ]),
    'netrx':     ('Network RX (KB/s)',           0, 10000, [
        ('silent',  'trapmf',[0,0,15,50]),
        ('low',     'trapmf',[30,100,250,500]),
        ('moderate','trimf', [400,900,1800]),
        ('high',    'trapmf',[1400,2500,5000,7000]),
        ('flood',   'trapmf',[5500,8000,10000,10000]),
    ]),
    'ext':       ('Unique Extensions',           0,    50, [
        ('single',  'trapmf',[0,0,2,4]),
        ('few',     'trapmf',[2,5,10,15]),
        ('several', 'trimf', [10,18,28]),
        ('many',    'trapmf',[22,32,42,48]),
        ('mass',    'trapmf',[40,46,50,50]),
    ]),
    'conn':      ('Active Connections',          0,   500, [
        ('none',    'trapmf',[0,0,2,6]),
        ('few',     'trapmf',[3,10,25,50]),
        ('moderate','trimf', [35,80,150]),
        ('many',    'trapmf',[120,200,320,420]),
        ('swarm',   'trapmf',[350,430,500,500]),
    ]),
    'ent':       ('Shannon Entropy (bits/byte)', 0,     8, [
        ('ordered', 'trapmf',[0.0,0.0,1.5,2.5]),
        ('low',     'trapmf',[1.8,2.8,3.6,4.5]),
        ('medium',  'trimf', [3.8,5.0,6.2]),
        ('high',    'trapmf',[5.5,6.5,7.2,7.8]),
        ('max',     'trapmf',[7.2,7.7,8.0,8.0]),
    ]),
    'priv':      ('Privilege Escalation Attempts', 0, 20, [
        ('none',    'trapmf',[0,0,0,1]),
        ('low',     'trapmf',[0,1,2,4]),
        ('moderate','trimf', [3,6,10]),
        ('high',    'trapmf',[8,12,16,18]),
        ('extreme', 'trapmf',[16,18,20,20]),
    ]),
}

# Scenario input values
SCENARIOS = {
    'Ransomware':  dict(cpu=75, mem=480,  fwrite=160, file_read=40,  nettx=80,   netrx=50,   ext=45, conn=12,  ent=7.8, priv=3),
    'Trojan':      dict(cpu=18, mem=210,  fwrite=8,   file_read=12,  nettx=4200, netrx=3500, ext=5,  conn=320, ent=3.2, priv=14),
    'Cryptominer': dict(cpu=96, mem=1400, fwrite=2,   file_read=5,   nettx=600,  netrx=200,  ext=2,  conn=20,  ent=2.8, priv=1),
    'Benign':      dict(cpu=12, mem=180,  fwrite=4,   file_read=8,   nettx=60,   netrx=90,   ext=3,  conn=4,   ent=2.1, priv=0),
    'Mixed':       dict(cpu=75, mem=550,  fwrite=170, file_read=45,  nettx=1800, netrx=1500, ext=38, conn=180, ent=7.8, priv=10),
}

# Actual FIS output scores (computed from running scenarios)
RESULTS = {
    'Ransomware':  {'Ransomware': 83.5, 'Trojan': 14.1, 'Cryptominer':  6.6},
    'Trojan':      {'Ransomware': 15.7, 'Trojan': 76.3, 'Cryptominer': 15.7},
    'Cryptominer': {'Ransomware':  5.4, 'Trojan':  5.4, 'Cryptominer': 83.7},
    'Benign':      {'Ransomware':  6.6, 'Trojan':  6.6, 'Cryptominer':  6.6},
    'Mixed':       {'Ransomware': 50.6, 'Trojan':  51.0,'Cryptominer':  9.0},
}

# ── FIGURE 1: System Architecture ────────────────────────────────────────────
def fig_architecture():
    fig, ax = plt.subplots(figsize=(13, 5))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.axis('off')

    def box(ax, x, y, w, h, label, sub='', color='#1e2a3a', tc=TEXT, sc=DIM):
        rect = FancyBboxPatch((x - w/2, y - h/2), w, h,
                              boxstyle='round,pad=0.02', linewidth=1.5,
                              edgecolor=color, facecolor=color, zorder=3)
        ax.add_patch(rect)
        ax.text(x, y + (0.06 if sub else 0), label, ha='center', va='center',
                color=tc, fontsize=10, fontweight='bold', zorder=4)
        if sub:
            ax.text(x, y - 0.10, sub, ha='center', va='center',
                    color=sc, fontsize=7.5, zorder=4)

    def arrow(ax, x1, x2, y=0.5):
        ax.annotate('', xy=(x2, y), xytext=(x1, y),
                    arrowprops=dict(arrowstyle='->', color=ACCENT_M, lw=2.0),
                    zorder=5)

    # 7 boxes — box half-width = 0.06, spacing ~0.15 apart
    steps = [
        (0.06, 'Process\nMonitor',    'psutil / PID',           '#0f2030', ACCENT_M),
        (0.21, 'Feature\nExtraction', '10 Behavioral\nMetrics', '#0f2030', TEXT),
        (0.36, 'Fuzzification',       'Membership\nFunctions',  '#0f2030', TEXT),
        (0.52, 'Inference\nEngine',   '34 Mamdani\nRules',      '#1a1030', ACCENT_C),
        (0.67, 'Defuzzification',     'Centroid\nMethod',       '#0f2030', TEXT),
        (0.81, 'Asymmetric\nEWMA',    'α↑=0.15  α↓=0.85\nFeedback State', '#1a150a', '#ffcc80'),
        (0.95, 'Verdict',             'R / T / C\nScore',       '#0f2030', ACCENT_R),
    ]

    for x, lbl, sub, col, tc in steps:
        box(ax, x, 0.5, 0.12, 0.50, lbl, sub, col, tc)

    for i in range(len(steps) - 1):
        arrow(ax, steps[i][0] + 0.06, steps[i+1][0] - 0.06)

    # Temporal feedback loop: curved arrow below EWMA block
    ax.annotate('',
        xy=(0.76, 0.17), xytext=(0.87, 0.17),
        arrowprops=dict(arrowstyle='<-', color='#ffcc80', lw=1.6,
                        connectionstyle='arc3,rad=-0.55'),
        annotation_clip=False)
    ax.text(0.815, 0.04, 'prev_score\n(t → t+1)', ha='center', va='center',
            color='#ffcc80', fontsize=7, style='italic')

    # annotation labels on arrows
    arrow_labels = ['raw\nmetrics', '10 crisp\nvalues', 'μ(x)', 'aggregated\noutput', 'raw R,T,C', 'smooth\nR,T,C']
    for i, lbl in enumerate(arrow_labels):
        xm = (steps[i][0] + steps[i+1][0]) / 2
        ax.text(xm, 0.30, lbl, ha='center', va='center', color=DIM,
                fontsize=7, style='italic')

    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.set_title('FuzzyShield — System Architecture', color=TEXT,
                 fontsize=13, fontweight='bold', pad=10)
    fig.tight_layout()
    out = os.path.join(FIGURES, 'fig_architecture.png')
    fig.savefig(out, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    print(f'[OK] {out}')

# ── FIGURE 2: All 10 Input MFs ────────────────────────────────────────────────
def fig_mf_all_inputs():
    keys = list(INPUTS.keys())
    fig, axes = plt.subplots(5, 2, figsize=(14, 18))
    fig.patch.set_facecolor(BG)

    for i, key in enumerate(keys):
        row, col = divmod(i, 2)
        ax = _ax(axes[row][col])
        label, lo, hi, mfs = INPUTS[key]
        x = np.linspace(lo, hi, 600)

        for name, mf_type, params in mfs:
            y = evalmf(x, mf_type, params)
            c = MF_CLR.get(name, '#aaaaaa')
            ax.plot(x, y, color=c, linewidth=2.2, label=name)
            ax.fill_between(x, y, alpha=0.08, color=c)

        ax.set_xlim(lo, hi); ax.set_ylim(-0.05, 1.18)
        ax.set_title(label, color=TEXT, fontsize=10, fontweight='bold', pad=5)
        ax.set_ylabel('μ(x)', color=DIM, fontsize=9)
        leg = ax.legend(fontsize=8, loc='upper right',
                        facecolor='#1c2230', edgecolor=GRID, labelcolor=TEXT,
                        framealpha=0.9)

    fig.suptitle('FuzzyShield — Input Variable Membership Functions',
                 color=TEXT, fontsize=14, fontweight='bold', y=1.005)
    fig.tight_layout(pad=1.8)
    out = os.path.join(FIGURES, 'fig_mf_all_inputs.png')
    fig.savefig(out, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    print(f'[OK] {out}')

# ── FIGURE 3: Output Variable MF ──────────────────────────────────────────────
def fig_mf_output():
    output_mfs = [
        ('none',     'trapmf', [0.00, 0.00, 0.05, 0.15]),
        ('trace',    'trapmf', [0.05, 0.15, 0.25, 0.35]),
        ('low',      'trapmf', [0.25, 0.35, 0.45, 0.55]),
        ('medium',   'trimf',  [0.45, 0.60, 0.75]),
        ('high',     'trapmf', [0.65, 0.75, 0.85, 0.92]),
        ('critical', 'trapmf', [0.85, 0.93, 1.00, 1.00]),
    ]
    out_colors = ['#3ac8ff','#72c464','#90d060','#f0df50','#ff9a30','#e83535']
    out_names  = ['Ransomware', 'Trojan', 'Cryptominer']
    score_vals = [0.835, 0.763, 0.837]
    score_clrs = [ACCENT_R, ACCENT_T, ACCENT_C]

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5))
    fig.patch.set_facecolor(BG)

    for k, (oname, sval, sclr) in enumerate(zip(out_names, score_vals, score_clrs)):
        ax = _ax(axes[k])
        x = np.linspace(0, 1, 500)
        for j, (name, mf_type, params) in enumerate(output_mfs):
            y = evalmf(x, mf_type, params)
            c = out_colors[j]
            ax.plot(x, y, color=c, linewidth=2.2, label=name)
            ax.fill_between(x, y, alpha=0.08, color=c)
        ax.axvline(sval, color=sclr, linewidth=2.2, linestyle='--',
                   label=f'{oname}: {sval*100:.1f}%')
        ax.set_xlim(0, 1); ax.set_ylim(-0.05, 1.18)
        ax.set_title(f'Output: {oname}', color=TEXT, fontsize=10, fontweight='bold')
        ax.set_xlabel('Defuzzified Threat Score', color=DIM, fontsize=9)
        ax.set_ylabel('μ(x)', color=DIM, fontsize=9)
        leg = ax.legend(fontsize=8, facecolor='#1c2230', edgecolor=GRID,
                        labelcolor=TEXT, framealpha=0.9)

    fig.suptitle('FuzzyShield — Output Variable Membership Functions (example: preset scenario scores)',
                 color=TEXT, fontsize=12, fontweight='bold')
    fig.tight_layout(pad=1.5)
    out = os.path.join(FIGURES, 'fig_mf_output.png')
    fig.savefig(out, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    print(f'[OK] {out}')

# ── FIGURE 4: Scenario Results Bar Chart ─────────────────────────────────────
def fig_scenario_results():
    scenarios = list(RESULTS.keys())
    threat_names = ['Ransomware', 'Trojan', 'Cryptominer']
    colors = [ACCENT_R, ACCENT_T, ACCENT_C]

    data = np.array([[RESULTS[sc][t] for t in threat_names] for sc in scenarios])

    x = np.arange(len(scenarios))
    width = 0.24
    offsets = [-width, 0, width]

    fig, ax = plt.subplots(figsize=(13, 6))
    fig.patch.set_facecolor(BG)
    _ax(ax)

    for i, (threat, color, offset) in enumerate(zip(threat_names, colors, offsets)):
        bars = ax.bar(x + offset, data[:, i], width, label=threat,
                      color=color, alpha=0.85, edgecolor=BG, linewidth=0.8)
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 1.2,
                    f'{h:.1f}', ha='center', va='bottom',
                    color=TEXT, fontsize=8, fontweight='bold')

    ax.axhline(70, color='#ffffff', linewidth=0.8, linestyle='--', alpha=0.35)
    ax.axhline(40, color='#ffffff', linewidth=0.8, linestyle=':', alpha=0.25)
    ax.text(4.6, 71.5, 'HIGH CONFIDENCE', color=DIM, fontsize=7.5, style='italic')
    ax.text(4.6, 41.5, 'LIKELY THREAT',   color=DIM, fontsize=7.5, style='italic')

    ax.set_xticks(x)
    ax.set_xticklabels(scenarios, color=TEXT, fontsize=11)
    ax.set_ylabel('Threat Score (%)', color=DIM, fontsize=10)
    ax.set_ylim(0, 100)
    ax.tick_params(axis='y', colors=DIM)
    leg = ax.legend(fontsize=10, facecolor='#1c2230', edgecolor=GRID,
                    labelcolor=TEXT, framealpha=0.9, loc='upper right')
    ax.set_title('FuzzyShield — Scenario Detection Results\n(Mamdani Centroid Defuzzification)',
                 color=TEXT, fontsize=13, fontweight='bold', pad=10)

    fig.tight_layout()
    out = os.path.join(FIGURES, 'fig_results.png')
    fig.savefig(out, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    print(f'[OK] {out}')

# ── FIGURE 5: Rule Category Distribution ──────────────────────────────────────
def fig_rule_distribution():
    categories  = ['Ransomware\n(12)', 'Trojan\n(9)', 'Cryptominer\n(8)',
                   'Mixed\n(3)', 'Benign\n(2)']
    counts      = [12, 9, 8, 3, 2]
    bar_colors  = [ACCENT_R, ACCENT_T, ACCENT_C, ACCENT_M, ACCENT_G]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.patch.set_facecolor(BG)

    # Bar chart
    _ax(ax1)
    bars = ax1.bar(categories, counts, color=bar_colors, edgecolor=BG,
                   linewidth=0.8, width=0.6)
    for bar, cnt in zip(bars, counts):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                 str(cnt), ha='center', va='bottom', color=TEXT,
                 fontsize=12, fontweight='bold')
    ax1.set_ylim(0, 16)
    ax1.set_ylabel('Number of Rules', color=DIM, fontsize=10)
    ax1.tick_params(axis='x', colors=TEXT, labelsize=9)
    ax1.tick_params(axis='y', colors=DIM)
    ax1.set_title('Rules per Category', color=TEXT, fontsize=11, fontweight='bold')

    # Pie chart
    ax2.set_facecolor(BG)
    wedge_props = dict(linewidth=2, edgecolor=BG)
    wedges, texts, autotexts = ax2.pie(
        counts, labels=None, colors=bar_colors,
        autopct='%1.0f%%', startangle=140,
        wedgeprops=wedge_props, pctdistance=0.72,
        textprops=dict(color=TEXT, fontsize=10),
    )
    for at in autotexts:
        at.set_color(BG); at.set_fontweight('bold'); at.set_fontsize(9)
    legend_labels = [f'{c} — {n} rules' for c, n in zip(['Ransomware','Trojan','Cryptominer','Mixed','Benign'], counts)]
    ax2.legend(wedges, legend_labels, loc='lower center', bbox_to_anchor=(0.5, -0.18),
               fontsize=9, facecolor='#1c2230', edgecolor=GRID, labelcolor=TEXT,
               framealpha=0.9, ncol=2)
    ax2.set_title('Rule Distribution (34 total)', color=TEXT, fontsize=11, fontweight='bold')

    fig.suptitle('FuzzyShield — Rule Base Composition', color=TEXT,
                 fontsize=13, fontweight='bold')
    fig.tight_layout(pad=2)
    out = os.path.join(FIGURES, 'fig_rule_dist.png')
    fig.savefig(out, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    print(f'[OK] {out}')

# ── FIGURE 6: Rule Surfaces ────────────────────────────────────────────────────
def fig_rule_surfaces():
    try:
        import fuzzy_shield as fs
    except Exception as e:
        print(f'[SKIP] Rule surfaces: {e}')
        return

    s = fs.sim
    N = 28

    surface_specs = [
        # (out_key, in1, range1, in2, range2, title, xlabel, ylabel, fixed_inputs, cmap)
        ('ransomware', 'fwrite', (0,200), 'ent', (0,8),
         'Ransomware | fwrite vs entropy', 'File Write Rate (MB/s)', 'Entropy (bits/byte)',
         dict(cpu=40, mem=300, file_read=20, nettx=100, netrx=80, ext=20, conn=8, priv=3),
         'Reds'),
        ('ransomware', 'fwrite', (0,200), 'ext', (0,50),
         'Ransomware | fwrite vs extensions', 'File Write Rate (MB/s)', 'Unique Extensions',
         dict(cpu=40, mem=300, file_read=20, nettx=100, netrx=80, conn=8, ent=6.5, priv=3),
         'Reds'),
        ('trojan', 'nettx', (0,10000), 'conn', (0,500),
         'Trojan | nettx vs connections', 'Network TX (KB/s)', 'Active Connections',
         dict(cpu=20, mem=200, fwrite=6, file_read=10, netrx=500, ext=5, ent=3.5, priv=10),
         'YlOrBr'),
        ('trojan', 'nettx', (0,10000), 'priv', (0,20),
         'Trojan | nettx vs privilege escalation', 'Network TX (KB/s)', 'Priv. Escalation',
         dict(cpu=20, mem=200, fwrite=6, file_read=10, netrx=500, ext=5, conn=200, ent=3.5),
         'YlOrBr'),
        ('cryptominer', 'cpu', (0,100), 'nettx', (0,10000),
         'Cryptominer | cpu vs nettx', 'CPU Usage (%)', 'Network TX (KB/s)',
         dict(mem=800, fwrite=2, file_read=4, netrx=100, ext=2, conn=15, ent=2.5, priv=1),
         'Purples'),
        ('cryptominer', 'cpu', (0,100), 'mem', (0,2048),
         'Cryptominer | cpu vs memory', 'CPU Usage (%)', 'Memory RSS (MB)',
         dict(fwrite=2, file_read=4, nettx=600, netrx=100, ext=2, conn=15, ent=2.5, priv=1),
         'Purples'),
    ]

    fig, axes = plt.subplots(2, 3, figsize=(16, 10),
                              subplot_kw={'projection': '3d'})
    fig.patch.set_facecolor(BG)

    for k, (out_key, in1, r1, in2, r2, title, xl, yl, fixed, cmap) in enumerate(surface_specs):
        ax = axes[k // 3][k % 3]
        ax.set_facecolor(PANEL)

        x_vals = np.linspace(r1[0], r1[1], N)
        y_vals = np.linspace(r2[0], r2[1], N)
        X, Y   = np.meshgrid(x_vals, y_vals)
        Z      = np.zeros_like(X)

        for i in range(N):
            for j in range(N):
                inp = dict(fixed)
                inp[in1] = X[i, j]
                inp[in2] = Y[i, j]
                try:
                    for key, val in inp.items():
                        s.input[key] = val
                    s.compute()
                    Z[i, j] = s.output[out_key]
                except Exception:
                    Z[i, j] = 0.0

        surf = ax.plot_surface(X, Y, Z, cmap=cmap, alpha=0.90,
                               edgecolor='none', antialiased=True)
        ax.set_xlabel(xl, color=DIM, fontsize=7, labelpad=6)
        ax.set_ylabel(yl, color=DIM, fontsize=7, labelpad=6)
        ax.set_zlabel('Threat Score', color=DIM, fontsize=7)
        ax.set_zlim(0, 1)
        ax.set_title(title, color=TEXT, fontsize=8.5, fontweight='bold', pad=6)
        ax.tick_params(colors=DIM, labelsize=6)
        ax.xaxis.pane.fill = False
        ax.yaxis.pane.fill = False
        ax.zaxis.pane.fill = False
        ax.xaxis.pane.set_edgecolor(GRID)
        ax.yaxis.pane.set_edgecolor(GRID)
        ax.zaxis.pane.set_edgecolor(GRID)
        ax.view_init(elev=25, azim=-45)
        cb = fig.colorbar(surf, ax=ax, fraction=0.03, pad=0.08)
        cb.ax.yaxis.set_tick_params(color=DIM, labelsize=7)
        plt.setp(cb.ax.yaxis.get_ticklabels(), color=DIM)

    fig.suptitle('FuzzyShield — 3D Rule Surfaces (Mamdani Inference)',
                 color=TEXT, fontsize=13, fontweight='bold')
    fig.tight_layout(pad=2)
    out = os.path.join(FIGURES, 'fig_surfaces.png')
    fig.savefig(out, dpi=130, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    print(f'[OK] {out}')

# ── FIGURE 7: Compound Threat Radar ──────────────────────────────────────────
def fig_compound_radar():
    scenario_data = {
        'Ransomware\n(SAFE)':       [83.5, 14.1,  6.6],
        'Trojan\n(HIGH CONF.)':     [15.7, 76.3, 15.7],
        'Cryptominer\n(HIGH CONF.)':[5.4,   5.4, 83.7],
        'Benign\n(SAFE)':           [6.6,   6.6,  6.6],
        'Mixed\n(RANSOMWARE\n+TROJAN)':[50.6, 51.0, 9.0],
    }
    threat_colors = [ACCENT_R, ACCENT_T, ACCENT_C]
    bar_width = 0.27
    x = np.arange(5)

    fig, ax = plt.subplots(figsize=(13, 6))
    fig.patch.set_facecolor(BG)
    _ax(ax)

    data = np.array(list(scenario_data.values()))
    sc_names = list(scenario_data.keys())

    for i, (tname, tc) in enumerate(zip(['Ransomware','Trojan','Cryptominer'], threat_colors)):
        bars = ax.bar(x + (i-1)*bar_width, data[:,i], bar_width,
                      label=tname, color=tc, alpha=0.82, edgecolor=BG, linewidth=0.7)
        for bar in bars:
            h = bar.get_height()
            if h > 8:
                ax.text(bar.get_x()+bar.get_width()/2, h+1,
                        f'{h:.0f}%', ha='center', va='bottom',
                        color=TEXT, fontsize=7.5, fontweight='bold')

    ax.axhline(70, color='#ffffff', lw=0.8, ls='--', alpha=0.35)
    ax.axhline(40, color='#ffffff', lw=0.8, ls=':', alpha=0.25)
    ax.axhline(35, color=ACCENT_M,  lw=1.0, ls=':', alpha=0.50,
               label='MIN_ACTIVE threshold (35%)')

    ax.set_xticks(x)
    ax.set_xticklabels(sc_names, color=TEXT, fontsize=9)
    ax.set_ylim(0, 100)
    ax.set_ylabel('Defuzzified Score (%)', color=DIM, fontsize=10)
    ax.tick_params(axis='y', colors=DIM)
    ax.legend(fontsize=9, facecolor='#1c2230', edgecolor=GRID,
              labelcolor=TEXT, framealpha=0.9)
    ax.set_title('FuzzyShield — Complete Scenario Detection Summary\n'
                 '(mixed scenario triggers compound RANSOMWARE + TROJAN verdict)',
                 color=TEXT, fontsize=12, fontweight='bold', pad=10)

    # Compound annotation
    ax.annotate('RANSOMWARE\n+ TROJAN', xy=(4, 51), xytext=(4, 75),
                ha='center', color=ACCENT_M, fontsize=9, fontweight='bold',
                arrowprops=dict(arrowstyle='->', color=ACCENT_M, lw=1.5))

    fig.tight_layout()
    out = os.path.join(FIGURES, 'fig_compound.png')
    fig.savefig(out, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close(fig)
    print(f'[OK] {out}')

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('Generating report figures...')
    fig_architecture()
    fig_mf_all_inputs()
    fig_mf_output()
    fig_scenario_results()
    fig_rule_distribution()
    fig_compound_radar()
    print('Generating 3D rule surfaces (may take ~60 seconds)...')
    fig_rule_surfaces()
    print('\nAll figures generated in figures/')
