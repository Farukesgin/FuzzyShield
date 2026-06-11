%% ================================================================
%  FuzzyShield — Behavioral Malware Classifier
%  MATLAB Fuzzy Logic Toolbox Implementation
%  Exact mirror of the Python (scikit-fuzzy) rule base
%
%  Requires: MATLAB Fuzzy Logic Toolbox
%
%  Usage:
%    fuzzy_shield                 % default: all scenarios
%    fuzzy_shield('ransomware')
%    fuzzy_shield('trojan')
%    fuzzy_shield('cryptominer')
%    fuzzy_shield('benign')
%    fuzzy_shield('mixed')
%    fuzzy_shield('all')          % all scenarios + save FIS file
%
%  Outputs:
%    - Membership Function plot per scenario
%    - Results Dashboard per scenario
%    - 3D Surface plots  (useful for reports)
%    - FuzzyShield.fis   (open in Fuzzy Logic Designer)
% ================================================================

function fuzzy_shield(scenario)

if nargin < 1
    scenario = 'all';
end

%% ============================================================
% 1. BUILD FIS
% ============================================================
fis = mamfis('Name', 'FuzzyShield_MalwareClassifier');
fis.DefuzzificationMethod = 'centroid';
fis.AndMethod             = 'min';
fis.OrMethod              = 'max';
fis.ImplicationMethod     = 'min';
fis.AggregationMethod     = 'max';

%% ============================================================
% 2. INPUT VARIABLES
% ============================================================

% ── CPU Usage (0-100 %) ──────────────────────────────────────
fis = addInput(fis, [0 100], 'Name', 'cpu');
fis = addMF(fis, 'cpu', 'trapmf', [0   0  10  20], 'Name', 'idle');
fis = addMF(fis, 'cpu', 'trapmf', [10 20  30  45], 'Name', 'low');
fis = addMF(fis, 'cpu', 'trimf',  [35 50  65],      'Name', 'moderate');
fis = addMF(fis, 'cpu', 'trapmf', [55 70  80  90], 'Name', 'high');
fis = addMF(fis, 'cpu', 'trapmf', [82 92 100 100], 'Name', 'extreme');

% ── Memory RSS (0-2048 MB) ───────────────────────────────────
fis = addInput(fis, [0 2048], 'Name', 'mem');
fis = addMF(fis, 'mem', 'trapmf', [0    0   64  150], 'Name', 'tiny');
fis = addMF(fis, 'mem', 'trapmf', [100 180  280  400], 'Name', 'small');
fis = addMF(fis, 'mem', 'trimf',  [300 512  800],       'Name', 'medium');
fis = addMF(fis, 'mem', 'trapmf', [700 900 1200 1500], 'Name', 'large');
fis = addMF(fis, 'mem', 'trapmf', [1300 1600 2048 2048], 'Name', 'huge');

% ── File Write Rate (0-200 MB/s) ─────────────────────────────
fis = addInput(fis, [0 200], 'Name', 'fwrite');
fis = addMF(fis, 'fwrite', 'trapmf', [0   0   2   6],   'Name', 'none');
fis = addMF(fis, 'fwrite', 'trapmf', [3  10  20  35],   'Name', 'low');
fis = addMF(fis, 'fwrite', 'trimf',  [25  50  80],       'Name', 'moderate');
fis = addMF(fis, 'fwrite', 'trapmf', [65 100 140 170],  'Name', 'high');
fis = addMF(fis, 'fwrite', 'trapmf', [150 175 200 200], 'Name', 'extreme');

% ── File Read Rate (0-200 MB/s) ──────────────────────────────
fis = addInput(fis, [0 200], 'Name', 'file_read');
fis = addMF(fis, 'file_read', 'trapmf', [0   0   3   8],   'Name', 'none');
fis = addMF(fis, 'file_read', 'trapmf', [5  15  30  50],   'Name', 'low');
fis = addMF(fis, 'file_read', 'trimf',  [35  60  95],       'Name', 'moderate');
fis = addMF(fis, 'file_read', 'trapmf', [80 110 150 175],  'Name', 'high');
fis = addMF(fis, 'file_read', 'trapmf', [160 180 200 200], 'Name', 'extreme');

% ── Network TX (0-10000 KB/s) ────────────────────────────────
fis = addInput(fis, [0 10000], 'Name', 'nettx');
fis = addMF(fis, 'nettx', 'trapmf', [0    0    10   40],   'Name', 'silent');
fis = addMF(fis, 'nettx', 'trapmf', [20   80  200  400],   'Name', 'low');
fis = addMF(fis, 'nettx', 'trimf',  [300  700 1400],        'Name', 'moderate');
fis = addMF(fis, 'nettx', 'trapmf', [1000 2000 4000 6000], 'Name', 'high');
fis = addMF(fis, 'nettx', 'trapmf', [4500 7000 10000 10000],'Name','flood');

% ── Network RX (0-10000 KB/s) ────────────────────────────────
fis = addInput(fis, [0 10000], 'Name', 'netrx');
fis = addMF(fis, 'netrx', 'trapmf', [0    0    15   50],   'Name', 'silent');
fis = addMF(fis, 'netrx', 'trapmf', [30  100  250  500],   'Name', 'low');
fis = addMF(fis, 'netrx', 'trimf',  [400  900 1800],        'Name', 'moderate');
fis = addMF(fis, 'netrx', 'trapmf', [1400 2500 5000 7000], 'Name', 'high');
fis = addMF(fis, 'netrx', 'trapmf', [5500 8000 10000 10000],'Name','flood');

% ── Unique Extensions (0-50) ─────────────────────────────────
fis = addInput(fis, [0 50], 'Name', 'ext');
fis = addMF(fis, 'ext', 'trapmf', [0   0   2   4],  'Name', 'single');
fis = addMF(fis, 'ext', 'trapmf', [2   5  10  15],  'Name', 'few');
fis = addMF(fis, 'ext', 'trimf',  [10  18  28],      'Name', 'several');
fis = addMF(fis, 'ext', 'trapmf', [22  32  42  48], 'Name', 'many');
fis = addMF(fis, 'ext', 'trapmf', [40  46  50  50], 'Name', 'mass');

% ── Active Connections (0-500) ───────────────────────────────
fis = addInput(fis, [0 500], 'Name', 'conn');
fis = addMF(fis, 'conn', 'trapmf', [0   0   2   6],    'Name', 'none');
fis = addMF(fis, 'conn', 'trapmf', [3  10  25  50],    'Name', 'few');
fis = addMF(fis, 'conn', 'trimf',  [35  80 150],        'Name', 'moderate');
fis = addMF(fis, 'conn', 'trapmf', [120 200 320 420],  'Name', 'many');
fis = addMF(fis, 'conn', 'trapmf', [350 430 500 500],  'Name', 'swarm');

% ── Output Entropy (0-8 bits/byte) ───────────────────────────
fis = addInput(fis, [0 8], 'Name', 'ent');
fis = addMF(fis, 'ent', 'trapmf', [0.0 0.0 1.5 2.5], 'Name', 'ordered');
fis = addMF(fis, 'ent', 'trapmf', [1.8 2.8 3.6 4.5], 'Name', 'low');
fis = addMF(fis, 'ent', 'trimf',  [3.8 5.0 6.2],      'Name', 'medium');
fis = addMF(fis, 'ent', 'trapmf', [5.5 6.5 7.2 7.8], 'Name', 'high');
fis = addMF(fis, 'ent', 'trapmf', [7.2 7.7 8.0 8.0], 'Name', 'max');

% ── Privilege Escalation Attempts (0-20) ─────────────────────
fis = addInput(fis, [0 20], 'Name', 'priv');
fis = addMF(fis, 'priv', 'trapmf', [0   0   0   1],  'Name', 'none');
fis = addMF(fis, 'priv', 'trapmf', [0   1   2   4],  'Name', 'low');
fis = addMF(fis, 'priv', 'trimf',  [3   6  10],       'Name', 'moderate');
fis = addMF(fis, 'priv', 'trapmf', [8  12  16  18],  'Name', 'high');
fis = addMF(fis, 'priv', 'trapmf', [16 18  20  20],  'Name', 'extreme');

%% ============================================================
% 3. OUTPUT VARIABLES
% ============================================================

out_mf_params = {
    'none',     'trapmf', [0.00 0.00 0.05 0.15];
    'trace',    'trapmf', [0.05 0.15 0.25 0.35];
    'low',      'trapmf', [0.25 0.35 0.45 0.55];
    'medium',   'trimf',  [0.45 0.60 0.75];
    'high',     'trapmf', [0.65 0.75 0.85 0.92];
    'critical', 'trapmf', [0.85 0.93 1.00 1.00];
};

out_names = {'ransomware', 'trojan', 'cryptominer'};
for i = 1:3
    fis = addOutput(fis, [0 1], 'Name', out_names{i});
    for j = 1:size(out_mf_params, 1)
        fis = addMF(fis, out_names{i}, ...
            out_mf_params{j,2}, out_mf_params{j,3}, ...
            'Name', out_mf_params{j,1});
    end
end

%% ============================================================
% 4. RULE BASE (34 rules — exact match with Python scikit-fuzzy)
%
%  Input column order:
%    1=cpu  2=mem  3=fwrite  4=file_read  5=nettx
%    6=netrx  7=ext  8=conn  9=ent  10=priv
%
%  Output column order:
%    1=ransomware  2=trojan  3=cryptominer
%
%  MF index order (per input, by definition order):
%    cpu:       1=idle    2=low  3=moderate  4=high  5=extreme
%    mem:       1=tiny    2=small  3=medium  4=large  5=huge
%    fwrite:    1=none    2=low  3=moderate  4=high  5=extreme
%    file_read: 1=none    2=low  3=moderate  4=high  5=extreme
%    nettx:     1=silent  2=low  3=moderate  4=high  5=flood
%    netrx:     1=silent  2=low  3=moderate  4=high  5=flood
%    ext:       1=single  2=few  3=several   4=many  5=mass
%    conn:      1=none    2=few  3=moderate  4=many  5=swarm
%    ent:       1=ordered 2=low  3=medium    4=high  5=max
%    priv:      1=none    2=low  3=moderate  4=high  5=extreme
%
%  Output MF index:
%    1=none  2=trace  3=low  4=medium  5=high  6=critical
%
%  Rule format: addRule(fis, ruleList)
%  ruleList columns: [in1..in10, out1 out2 out3, weight, conn(1=AND)]
% ============================================================

ruleList = [
% cpu mem fwr frd ntx nrx ext con ent prv | R   T   C   | w  AND
% ── RANSOMWARE (12 rules) ────────────────────────────────────────────
  0   0   5   0   0   0   4   0   5   0     6   1   1     1   1;  % R1:  fwrite=extreme & ext=many     & ent=max       → R:critical T:none  C:none
  0   0   4   0   0   0   4   0   4   0     5   2   1     1   1;  % R2:  fwrite=high    & ext=many     & ent=high      → R:high    T:trace C:none
  0   0   5   0   0   0   0   2   4   0     5   2   1     1   1;  % R3:  fwrite=extreme & conn=few     & ent=high      → R:high    T:trace C:none
  0   0   4   0   0   0   3   0   4   0     4   2   1     1   1;  % R4:  fwrite=high    & ext=several  & ent=high      → R:medium  T:trace C:none
  4   0   5   0   0   0   5   0   0   0     5   1   1     1   1;  % R5:  cpu=high & fwrite=extreme     & ext=mass      → R:high    T:none  C:none
  0   0   4   0   0   0   0   0   5   3     5   2   1     1   1;  % R6:  ent=max  & fwrite=high & priv=moderate        → R:high    T:trace C:none
  0   0   3   0   0   0   4   0   3   0     4   2   1     1   1;  % R7:  fwrite=moderate & ext=many    & ent=medium    → R:medium  T:trace C:none
  0   0   4   0   0   0   3   0   5   0     5   1   1     1   1;  % R25: fwrite=high    & ext=several  & ent=max       → R:high    T:none  C:none
  0   0   3   0   0   0   3   0   5   0     5   1   1     1   1;  % R26: fwrite=moderate& ext=several  & ent=max       → R:high    T:none  C:none
  0   0   4   0   0   0   0   1   5   0     4   1   1     1   1;  % R27: fwrite=high    & conn=none    & ent=max       → R:medium  T:none  C:none
  0   0   5   2   0   0   0   0   5   0     6   1   1     1   1;  % R28: fwrite=extreme & file_read=low & ent=max      → R:critical T:none C:none
  0   0   5   3   0   0   5   0   0   0     5   2   1     1   1;  % R29: file_read=mod  & fwrite=extreme & ext=mass    → R:high    T:trace C:none

% ── TROJAN (9 rules) ─────────────────────────────────────────────────
  0   0   0   0   4   0   0   4   0   4     1   6   1     1   1;  % R8:  nettx=high    & conn=many    & priv=high     → R:none    T:critical C:none
  0   0   0   0   5   0   0   5   0   0     1   6   1     1   1;  % R9:  nettx=flood   & conn=swarm                   → R:none    T:critical C:none
  0   0   0   0   4   4   0   4   0   0     2   5   2     1   1;  % R10: nettx=high    & netrx=high   & conn=many     → R:trace   T:high    C:trace
  2   0   0   0   0   0   0   4   0   4     1   5   1     1   1;  % R11: cpu=low & conn=many & priv=high              → R:none    T:high    C:none
  0   0   0   0   3   0   0   4   0   5     2   5   1     1   1;  % R12: nettx=moderate & conn=many  & priv=extreme   → R:trace   T:high    C:none
  0   0   2   0   0   4   0   4   0   0     1   4   2     1   1;  % R13: fwrite=low    & netrx=high  & conn=many      → R:none    T:medium  C:trace
  0   0   0   0   5   0   0   0   0   5     1   6   1     1   1;  % R14: nettx=flood   & priv=extreme                 → R:none    T:critical C:none
  0   0   0   0   4   0   0   3   0   3     1   4   2     1   1;  % R15: conn=moderate & nettx=high  & priv=moderate  → R:none    T:medium  C:trace
  0   0   0   2   4   0   0   4   0   0     2   5   1     1   1;  % R30: file_read=low & nettx=high  & conn=many      → R:trace   T:high    C:none

% ── CRYPTOMINER (8 rules) ────────────────────────────────────────────
  5   0   1   0   3   0   0   0   0   0     1   1   6     1   1;  % R16: cpu=extreme & fwrite=none & nettx=moderate   → R:none T:none C:critical
  5   4   0   0   3   0   0   0   0   0     1   1   6     1   1;  % R17: cpu=extreme & mem=large   & nettx=moderate   → R:none T:none C:critical
  4   0   1   0   3   0   0   2   0   0     1   2   5     1   1;  % R18: cpu=high & fwrite=none & nettx=moderate & conn=few → R:none T:trace C:high
  5   0   1   0   0   0   0   2   2   0     1   1   5     1   1;  % R19: cpu=extreme & fwrite=none & conn=few & ent=low  → R:none T:none C:high
  4   5   0   0   3   0   0   0   0   0     1   1   5     1   1;  % R20: cpu=high & mem=huge & nettx=moderate         → R:none T:none C:high
  3   0   1   0   3   0   0   3   0   0     1   2   3     1   1;  % R21: cpu=moderate & fwrite=none & nettx=moderate & conn=moderate → R:none T:trace C:low
  5   0   1   0   0   0   0   2   0   0     1   1   5     1   1;  % R22: cpu=extreme & fwrite=none & conn=few         → R:none T:none C:high
  5   0   1   0   0   0   0   2   1   0     1   1   6     1   1;  % R24: cpu=extreme & fwrite=none & conn=few & ent=ordered → R:none T:none C:critical

% ── MIXED / AMBIGUOUS (3 rules) ──────────────────────────────────────
  4   0   4   0   4   0   0   0   0   0     4   4   2     1   1;  % M1: cpu=high & fwrite=high & nettx=high    → R:medium T:medium C:trace
  0   0   0   0   3   0   0   0   4   3     4   4   2     1   1;  % M2: priv=moderate & ent=high & nettx=mod   → R:medium T:medium C:trace
  0   0   0   0   0   0   0   4   5   5     5   5   1     1   1;  % M3: priv=extreme  & ent=max  & conn=many   → R:high   T:high   C:none

% ── BENIGN (2 rules) ─────────────────────────────────────────────────
  1   0   1   0   1   0   0   1   0   0     1   1   1     1   1;  % B1: cpu=idle & fwrite=none & nettx=silent & conn=none → safe
  1   0   0   0   0   0   1   0   1   1     1   1   1     1   1;  % B2: cpu=idle & ext=single  & ent=ordered  & priv=none → safe
];

fis = addRule(fis, ruleList);

%% ============================================================
% 5. SAVE FIS FILE
% ============================================================
writeFIS(fis, 'FuzzyShield');
fprintf('\n[OK] FIS saved: FuzzyShield.fis\n');
fprintf('     Open in Fuzzy Logic Designer: fuzzyLogicDesigner(''FuzzyShield.fis'')\n\n');

%% ============================================================
% 6. SCENARIOS
% ============================================================
scenarios.ransomware  = [75, 480,  160, 40,  80,   50,   45, 12,  7.8, 3 ];
scenarios.trojan      = [18, 210,  8,   12,  4200, 3500, 5,  320, 3.2, 14];
scenarios.cryptominer = [96, 1400, 2,   5,   600,  200,  2,  20,  2.8, 1 ];
scenarios.benign      = [12, 180,  4,   8,   60,   90,   3,  4,   2.1, 0 ];
scenarios.mixed       = [75, 550, 170,  45,  1800, 1500, 38, 180, 7.8, 10];

input_names  = {'cpu','mem','fwrite','file_read','nettx','netrx','ext','conn','ent','priv'};
input_units  = {'%','MB','MB/s','MB/s','KB/s','KB/s','','','bits/B',''};
input_ranges = [100, 2048, 200, 200, 10000, 10000, 50, 500, 8, 20];

%% ============================================================
% 7. ASYMMETRIC EWMA FEEDBACK CONSTANTS
%    Mirrors Python EWMAFeedback class (fuzzy_shield.py §7b)
%    alpha_rise = 0.15 → fast upward response (new threat dominates)
%    alpha_fall = 0.85 → slow downward decay  (burst-pause evasion blocked)
%    Formula: s_t = alpha * s_{t-1} + (1 - alpha) * raw
% ============================================================
ALPHA_RISE = 0.15;
ALPHA_FALL = 0.85;

%% ============================================================
% 8. RUN
% ============================================================
if strcmp(scenario, 'all')
    sc_list = fieldnames(scenarios);
else
    sc_list = {scenario};
end

for s = 1:length(sc_list)
    sc_name  = sc_list{s};
    sc_input = scenarios.(sc_name);

    fprintf('=================================================================\n');
    fprintf('  Scenario: %s\n', upper(sc_name));
    fprintf('=================================================================\n');

    % Raw FIS output (same as Python run_inference)
    raw_out = evalfis(fis, sc_input);
    R_raw   = raw_out(1);
    T_raw   = raw_out(2);
    C_raw   = raw_out(3);

    % EWMA step from cold state (prev=0) — demonstrates temporal feedback
    % On first window: smoothed = (1-alpha_rise)*raw = 0.85*raw
    % Verdict and primary plots use RAW scores, matching Python scenario mode
    [smooth, ~] = ewma_step([R_raw T_raw C_raw], [0 0 0], ALPHA_RISE, ALPHA_FALL);
    R_smooth = smooth(1);  T_smooth = smooth(2);  C_smooth = smooth(3);

    print_terminal_report(sc_name, sc_input, R_raw, T_raw, C_raw, ...
        R_smooth, T_smooth, C_smooth, input_names, input_units, input_ranges, fis);

    fig1 = plot_membership_functions(fis, sc_input, sc_name, input_names, input_units);
    saveas(fig1, sprintf('fuzzy_results_%s.png', sc_name));
    fprintf('[OK] Saved: fuzzy_results_%s.png\n', sc_name);

    fig2 = plot_results_dashboard(sc_name, sc_input, R_raw, T_raw, C_raw, ...
        R_smooth, T_smooth, C_smooth, input_names, input_units, input_ranges, fis);
    saveas(fig2, sprintf('fuzzy_output_%s.png', sc_name));
    fprintf('[OK] Saved: fuzzy_output_%s.png\n', sc_name);

    fprintf('\n');
end

%% ============================================================
% 9. 3D SURFACE PLOTS
% ============================================================
fprintf('Generating 3D Surface plots...\n');
fig3 = plot_3d_surfaces(fis);
saveas(fig3, 'fuzzy_3d_surfaces.png');
fprintf('[OK] Saved: fuzzy_3d_surfaces.png\n');

fprintf('\n[OK] All done! Open .png files for your report.\n');
fprintf('    Fuzzy Logic Designer: fuzzyLogicDesigner(''FuzzyShield.fis'')\n\n');

end % function fuzzy_shield


%% ================================================================
%  HELPER FUNCTIONS
%% ================================================================

function print_terminal_report(sc_name, inputs, R, T, C, R_s, T_s, C_s, ...
    in_names, in_units, in_ranges, fis)
% R,T,C   = raw FIS scores  (used for verdict — matches Python scenario mode)
% R_s,T_s,C_s = EWMA smoothed  (shown in temporal feedback section)

W = 72;
sep = repmat('-', 1, W);
fprintf('\n%s\n', repmat('=', 1, W));
fprintf('%s\n', center_str('FuzzyShield -- Behavioral Malware Classifier', W));
fprintf('%s\n', center_str('MATLAB Fuzzy Logic Toolbox -- Mamdani Centroid', W));
fprintf('%s\n\n', repmat('=', 1, W));

% ── Input Variables ───────────────────────────────────────────
fprintf('INPUT VARIABLES\n%s\n', sep);
for i = 1:length(in_names)
    pct     = inputs(i) / in_ranges(i);
    filled  = round(pct * 20);
    bar_str = [repmat('#', 1, filled), repmat('.', 1, 20-filled)];
    fprintf('  %-22s %8.2f %-6s [%s] %5.1f%%\n', ...
        in_names{i}, inputs(i), in_units{i}, bar_str, pct*100);
end

% ── Fuzzy Membership Activations ─────────────────────────────
fprintf('\nFUZZY MEMBERSHIP ACTIVATIONS\n%s\n', sep);
for i = 1:length(fis.Inputs)
    inp_obj    = fis.Inputs(i);
    val        = inputs(i);
    active_str = '';
    for j = 1:length(inp_obj.MembershipFunctions)
        mf_obj = inp_obj.MembershipFunctions(j);
        deg    = evalmf(mf_obj, val);
        if deg > 0.001
            active_str = [active_str, sprintf('%s=%.3f  ', mf_obj.Name, deg)];
        end
    end
    if ~isempty(strtrim(active_str))
        fprintf('  %-22s  %s\n', in_names{i}, strtrim(active_str));
    end
end

% ── Threat Classification Scores ──────────────────────────────
fprintf('\nTHREAT CLASSIFICATION SCORES\n%s\n', sep);
threats = {'Ransomware', 'Trojan', 'Cryptominer'};
scores  = [R, T, C];
icons   = {'[R]', '[T]', '[C]'};
for i = 1:3
    p      = scores(i);
    filled = round(p * 30);
    bar_str = [repmat('#', 1, filled), repmat('.', 1, 30-filled)];
    fprintf('  %s %-14s [%s] %5.1f%%  %s\n', ...
        icons{i}, threats{i}, bar_str, p*100, get_level(p));
end

% ── Temporal Feedback — Asymmetric EWMA ──────────────────────
fprintf('\nTEMPORAL FEEDBACK  (Asymmetric EWMA  alpha_rise=0.15  alpha_fall=0.85)\n%s\n', sep);
raw_arr  = [R,   T,   C  ];
smt_arr  = [R_s, T_s, C_s];
for i = 1:3
    d = smt_arr(i) - raw_arr(i);
    if d > 0.005
        arrow_str = 'held up ^';
    elseif d < -0.005
        arrow_str = 'decay   v';
    else
        arrow_str = 'stable  -';
    end
    fprintf('  %-14s  raw %5.1f%%  %s  smoothed %5.1f%%  (delta %+.1f%%)\n', ...
        threats{i}, raw_arr(i)*100, arrow_str, smt_arr(i)*100, d*100);
end
fprintf('  [cold state: smoothed = 0.85*raw on first window -- no prior temporal context]\n');

% ── Verdict (uses raw scores, consistent with Python scenario mode) ──
[threat_type, confidence] = get_verdict(R, T, C);
fprintf('\nVERDICT\n%s\n', sep);
fprintf('  >> %s: %s\n', confidence, upper(threat_type));
fprintf('  Max threat score: %.1f%%\n', max([R,T,C])*100);
fprintf('%s\n\n', repmat('=', 1, W));
end


function fig = plot_membership_functions(fis, inputs, sc_name, in_names, in_units)
fig = figure('Name', sprintf('MF -- %s', upper(sc_name)), ...
    'Color', [0.05 0.05 0.08], 'Position', [50 50 1400 900]);

n_inputs = length(fis.Inputs);
cols = 2; rows = 5;

colors_by_term = containers.Map( ...
    {'idle','tiny','none','single','silent','ordered', ...
     'low','small','few', ...
     'moderate','medium','several', ...
     'high','large','many', ...
     'extreme','huge','mass','flood','swarm','max','critical'}, ...
    {[0.30 0.76 1.00], [0.30 0.76 1.00], [0.30 0.76 1.00], ...
     [0.30 0.76 1.00], [0.30 0.76 1.00], [0.30 0.76 1.00], ...
     [0.51 0.78 0.48], [0.51 0.78 0.48], [0.51 0.78 0.48], ...
     [1.00 0.95 0.46], [1.00 0.95 0.46], [1.00 0.95 0.46], ...
     [1.00 0.72 0.30], [1.00 0.72 0.30], [1.00 0.72 0.30], ...
     [0.90 0.32 0.36], [0.90 0.32 0.36], [0.90 0.32 0.36], ...
     [0.90 0.32 0.36], [0.90 0.32 0.36], [0.90 0.32 0.36], ...
     [0.94 0.60 0.60]});

for i = 1:n_inputs
    ax = subplot(rows, cols, i);
    set(ax, 'Color', [0.09 0.11 0.14], 'XColor', [0.55 0.60 0.65], ...
        'YColor', [0.55 0.60 0.65], 'GridColor', [0.13 0.16 0.20]);
    hold(ax, 'on'); grid(ax, 'on');

    inp = fis.Inputs(i);
    u   = linspace(inp.Range(1), inp.Range(2), 500);
    val = inputs(i);

    for j = 1:length(inp.MembershipFunctions)
        mf_obj  = inp.MembershipFunctions(j);
        mf_name = mf_obj.Name;
        mf_vals = evalmf(mf_obj, u);

        if isKey(colors_by_term, mf_name)
            c = colors_by_term(mf_name);
        else
            c = [0.67 0.67 0.67];
        end

        plot(ax, u, mf_vals, 'Color', c, 'LineWidth', 2);
        area(ax, u, mf_vals, 'FaceColor', c, 'FaceAlpha', 0.06, 'EdgeColor', 'none');

        deg = evalmf(mf_obj, val);
        if deg > 0.01
            clipped = min(mf_vals, deg);
            area(ax, u, clipped, 'FaceColor', c, 'FaceAlpha', 0.30, 'EdgeColor', 'none');
        end
    end

    xline(ax, val, '--', 'Color', [0.00 0.90 1.00], 'LineWidth', 1.8);

    title(ax, sprintf('%s (%s)', in_names{i}, in_units{i}), ...
        'Color', [0.90 0.93 0.95], 'FontSize', 9, 'FontWeight', 'bold');
    ylabel(ax, 'mu(x)', 'Color', [0.55 0.60 0.65], 'FontSize', 8);
    ylim(ax, [0 1.1]);
    xlim(ax, inp.Range);

    term_names = {inp.MembershipFunctions.Name};
    lh = legend(ax, term_names, 'Location', 'northeast', 'FontSize', 7);
    set(lh, 'Color', [0.13 0.16 0.20], 'TextColor', [0.80 0.83 0.87], ...
        'EdgeColor', [0.19 0.23 0.32]);
end

sgtitle(fig, sprintf('FuzzyShield -- Membership Functions | Scenario: %s', upper(sc_name)), ...
    'Color', [0.90 0.93 0.95], 'FontSize', 13, 'FontWeight', 'bold');
end


function fig = plot_results_dashboard(sc_name, inputs, R, T, C, R_s, T_s, C_s, ...
    in_names, in_units, in_ranges, fis)
% R,T,C       = raw FIS scores (verdict + primary plots)
% R_s,T_s,C_s = EWMA smoothed (marker overlay on bar chart)
% Layout mirrors Python GridSpec(3,3):
%   Row 1: [scores bar (cols 1-2)] [radar (col 3)]
%   Row 2: [heatmap  (cols 1-2)] [input table (col 3)]
%   Row 3: [R output MF] [T output MF] [C output MF]

fig = figure('Name', sprintf('Results -- %s', upper(sc_name)), ...
    'Color', [0.05 0.05 0.08], 'Position', [100 30 1500 1050]);

bg   = [0.07 0.08 0.11];
clrs = [0.97 0.32 0.29; 0.89 0.70 0.25; 0.74 0.55 1.00];
threats_lbl = {'Ransomware', 'Trojan', 'Cryptominer'};
u_out = linspace(0, 1, 500);

% ── (A) Threat Score Bar Chart — subplot(3,3,[1 2]) ───────────
ax1 = subplot(3,3,[1 2]);
set(ax1, 'Color', bg, 'XColor', [0.55 0.60 0.65], 'YColor', [0.55 0.60 0.65]);
hold(ax1, 'on'); grid(ax1, 'on');

raw_pct  = [R, T, C]   * 100;
smt_pct  = [R_s, T_s, C_s] * 100;

bh = barh(ax1, raw_pct, 0.45, 'FaceColor', 'flat');
bh.CData = clrs;
for i = 1:3
    text(ax1, raw_pct(i)+0.5, i, sprintf('%.1f%%', raw_pct(i)), ...
        'Color', [0.90 0.93 0.95], 'FontSize', 12, 'FontWeight', 'bold', ...
        'VerticalAlignment', 'middle');
    % EWMA smoothed marker (triangle)
    plot(ax1, smt_pct(i), i, 'v', ...
        'MarkerFaceColor', clrs(i,:)*0.65, ...
        'MarkerEdgeColor', [0.90 0.93 0.95], 'MarkerSize', 9, 'LineWidth', 0.8);
end
set(ax1, 'YTickLabel', threats_lbl, 'FontSize', 10);
xline(ax1, 40, ':', 'Color', [0.30 0.30 0.30], 'LineWidth', 1);
xline(ax1, 70, ':', 'Color', [0.40 0.40 0.40], 'LineWidth', 1);
text(ax1, 40.5, 0.45, '40%', 'Color', [0.35 0.35 0.35], 'FontSize', 8);
text(ax1, 70.5, 0.45, '70%', 'Color', [0.45 0.45 0.45], 'FontSize', 8);
xlim(ax1, [0 115]);
title(ax1, 'Threat Classification Scores  (bars = raw FIS  |  triangle = EWMA smoothed)', ...
    'Color', [0.90 0.93 0.95], 'FontSize', 10, 'FontWeight', 'bold');
xlabel(ax1, 'Defuzzified Probability (%)', 'Color', [0.55 0.60 0.65]);

% ── (B) Radar Chart — subplot(3,3,3) ─────────────────────────
ax2 = subplot(3,3,3);
set(ax2, 'Color', bg, 'XTick', [], 'YTick', [], 'Box', 'off');
hold(ax2, 'on');

theta_rad = [90, 90-120, 90-240] * pi/180;
sv       = [R, T, C];
t_circ   = linspace(0, 2*pi, 200);
for gl = [0.25 0.5 0.75 1.0]
    plot(ax2, cos(t_circ)*gl, sin(t_circ)*gl, 'Color', [0.20 0.23 0.28], 'LineWidth', 0.5);
end
for i = 1:3
    plot(ax2, [0, cos(theta_rad(i))], [0, sin(theta_rad(i))], ...
        'Color', [0.25 0.28 0.33], 'LineWidth', 1);
end
px = cos(theta_rad) .* sv;
py = sin(theta_rad) .* sv;
fill(ax2, [px px(1)], [py py(1)], [0.00 0.90 1.00], ...
    'FaceAlpha', 0.18, 'EdgeColor', [0.00 0.90 1.00], 'LineWidth', 2);
for i = 1:3
    text(ax2, cos(theta_rad(i))*1.28, sin(theta_rad(i))*1.28, ...
        sprintf('%s\n%.0f%%', threats_lbl{i}, sv(i)*100), ...
        'Color', clrs(i,:), 'FontSize', 8, 'FontWeight', 'bold', ...
        'HorizontalAlignment', 'center');
end
xlim(ax2, [-1.7 1.7]); ylim(ax2, [-1.7 1.7]); axis(ax2, 'equal');
title(ax2, 'Threat Radar', 'Color', [0.90 0.93 0.95], 'FontSize', 9);

% ── (C) Input Membership Heatmap — subplot(3,3,[4 5]) ────────
ax3 = subplot(3,3,[4 5]);
set(ax3, 'Color', bg, 'XColor', [0.55 0.60 0.65], 'YColor', [0.55 0.60 0.65]);

n_in    = length(fis.Inputs);
n_terms = 5;
heat    = zeros(n_in, n_terms);
for i = 1:n_in
    for j = 1:min(length(fis.Inputs(i).MembershipFunctions), n_terms)
        heat(i,j) = evalmf(fis.Inputs(i).MembershipFunctions(j), inputs(i));
    end
end
imagesc(ax3, heat');
colormap(ax3, hot);
caxis(ax3, [0 1]);
cb = colorbar(ax3);
cb.Color = [0.55 0.60 0.65];
cb.Label.String = 'mu(x)';  cb.Label.Color = [0.55 0.60 0.65];
xlabels_s = {'CPU','MEM','FWR','FRD','TX','RX','EXT','CON','ENT','PRV'};
ylabels_s = {'VeryLow','Low','Medium','High','VeryHigh'};
set(ax3, 'XTick', 1:n_in, 'XTickLabel', xlabels_s(1:n_in), ...
    'YTick', 1:n_terms, 'YTickLabel', ylabels_s, 'FontSize', 8);
for i = 1:n_in
    for j = 1:n_terms
        if heat(i,j) > 0.05
            text(ax3, i, j, sprintf('%.2f', heat(i,j)), ...
                'HorizontalAlignment', 'center', 'FontSize', 7, ...
                'Color', iff(heat(i,j)>0.5, 'black', 'white'));
        end
    end
end
title(ax3, 'Input Membership Degree Heatmap', ...
    'Color', [0.90 0.93 0.95], 'FontSize', 10, 'FontWeight', 'bold');

% ── (D) Input Summary Table — subplot(3,3,6) ─────────────────
ax_tbl = subplot(3,3,6);
set(ax_tbl, 'Color', bg, 'XTick', [], 'YTick', [], 'Box', 'off');
axis(ax_tbl, [0 1 0 1]);  hold(ax_tbl, 'on');
n_rows = length(in_names);
step   = 0.88 / n_rows;
for i = 1:n_rows
    yc = 0.94 - (i-0.5)*step;
    row_bg = iff(mod(i,2)==0, [0.13 0.16 0.20], [0.09 0.11 0.14]);
    fill(ax_tbl, [0.01 0.99 0.99 0.01], yc + step/2*[-1 -1 1 1], ...
        row_bg, 'EdgeColor', 'none');
    text(ax_tbl, 0.04, yc, in_names{i}, ...
        'Color', [0.78 0.83 0.87], 'FontSize', 7.5, 'VerticalAlignment', 'middle');
    text(ax_tbl, 0.97, yc, sprintf('%.2f %s', inputs(i), in_units{i}), ...
        'Color', [0.78 0.83 0.87], 'FontSize', 7.5, ...
        'VerticalAlignment', 'middle', 'HorizontalAlignment', 'right');
end
title(ax_tbl, 'Input Summary', 'Color', [0.90 0.93 0.95], 'FontSize', 9, 'FontWeight', 'bold');
xlim(ax_tbl,[0 1]); ylim(ax_tbl,[0 1]);

% ── (E) Output MF subplots — subplot(3,3,7/8/9) ──────────────
out_var_names = {'ransomware','trojan','cryptominer'};
out_scores    = [R, T, C];
out_smooth    = [R_s, T_s, C_s];

for k = 1:3
    ax_out = subplot(3,3, 6+k);
    set(ax_out, 'Color', bg, ...
        'XColor', [0.55 0.60 0.65], 'YColor', [0.55 0.60 0.65]);
    hold(ax_out, 'on');  grid(ax_out, 'on');
    c = clrs(k,:);

    for j = 1:length(fis.Outputs(k).MembershipFunctions)
        mf_v = evalmf(fis.Outputs(k).MembershipFunctions(j), u_out);
        plot(ax_out, u_out, mf_v, 'Color', [c 0.55], 'LineWidth', 1.5);
        area(ax_out, u_out, mf_v, 'FaceColor', c, 'FaceAlpha', 0.05, 'EdgeColor', 'none');
    end
    % Raw centroid (thick dashed)
    xline(ax_out, out_scores(k), 'Color', c, 'LineWidth', 2.5, 'LineStyle', '--');
    text(ax_out, out_scores(k), 1.13, sprintf('%.1f%%', out_scores(k)*100), ...
        'Color', c, 'FontSize', 9, 'FontWeight', 'bold', 'HorizontalAlignment', 'center');
    % EWMA smoothed centroid (thin dotted)
    if abs(out_smooth(k) - out_scores(k)) > 0.005
        xline(ax_out, out_smooth(k), 'Color', c*0.65, 'LineWidth', 1.2, 'LineStyle', ':');
    end

    % Capitalise first letter for title
    name_cap = [upper(out_var_names{k}(1)), out_var_names{k}(2:end)];
    title(ax_out, [name_cap, ' Output MF'], ...
        'Color', [0.90 0.93 0.95], 'FontSize', 9, 'FontWeight', 'bold');
    xlabel(ax_out, 'Probability', 'Color', [0.55 0.60 0.65], 'FontSize', 8);
    if k == 1
        ylabel(ax_out, 'mu(y)', 'Color', [0.55 0.60 0.65], 'FontSize', 8);
    end
    xlim(ax_out, [0 1]);  ylim(ax_out, [0 1.22]);
    for sp_obj = ax_out.XAxis; sp_obj.FontSize = 7; end
end

% ── Super title ───────────────────────────────────────────────
[threat_type, confidence] = get_verdict(R, T, C);
sgtitle(fig, sprintf('FuzzyShield Results | %s | Verdict: %s -- %s  (EWMA feedback integrated)', ...
    upper(sc_name), confidence, upper(threat_type)), ...
    'Color', [0.90 0.93 0.95], 'FontSize', 12, 'FontWeight', 'bold');
end


function fig = plot_3d_surfaces(fis)
fig = figure('Name', 'FuzzyShield -- 3D Rule Surfaces', ...
    'Color', [0.05 0.05 0.08], 'Position', [50 50 1500 1000]);

% {out_idx, in1_idx, in2_idx, title, xlabel, ylabel}
surface_defs = {
    1, 3, 9,  'Ransomware  |  fwrite vs entropy',    'fwrite (MB/s)',    'entropy (bits/B)';
    1, 3, 7,  'Ransomware  |  fwrite vs ext',         'fwrite (MB/s)',    'unique ext';
    2, 5, 8,  'Trojan  |  nettx vs connections',      'nettx (KB/s)',     'connections';
    2, 5, 10, 'Trojan  |  nettx vs priv-esc',         'nettx (KB/s)',     'priv-esc';
    3, 1, 5,  'Cryptominer  |  cpu vs nettx',         'cpu (%)',          'nettx (KB/s)';
    3, 1, 2,  'Cryptominer  |  cpu vs memory',        'cpu (%)',          'memory (MB)';
};

n_res = 40;

for k = 1:size(surface_defs, 1)
    out_idx = surface_defs{k, 1};
    in1_idx = surface_defs{k, 2};
    in2_idx = surface_defs{k, 3};
    ttl     = surface_defs{k, 4};
    xl      = surface_defs{k, 5};
    yl      = surface_defs{k, 6};

    in1_range = fis.Inputs(in1_idx).Range;
    in2_range = fis.Inputs(in2_idx).Range;

    x = linspace(in1_range(1), in1_range(2), n_res);
    y = linspace(in2_range(1), in2_range(2), n_res);
    [X, Y] = meshgrid(x, y);
    Z = zeros(size(X));

    default_inputs = [12, 180, 4, 8, 60, 90, 3, 4, 2.1, 0];

    for i = 1:n_res
        for j = 1:n_res
            inp = default_inputs;
            inp(in1_idx) = X(i,j);
            inp(in2_idx) = Y(i,j);
            try
                out    = evalfis(fis, inp);
                Z(i,j) = out(out_idx);
            catch
                Z(i,j) = 0;
            end
        end
    end

    ax = subplot(2, 3, k);
    set(ax, 'Color', [0.09 0.11 0.14], 'XColor', [0.70 0.73 0.77], ...
        'YColor', [0.70 0.73 0.77], 'ZColor', [0.70 0.73 0.77]);

    surf(ax, X, Y, Z, 'EdgeAlpha', 0.15, 'FaceAlpha', 0.90);

    if out_idx == 1
        colormap(ax, flipud(hot));
    elseif out_idx == 2
        colormap(ax, parula);
    else
        colormap(ax, cool);
    end

    shading(ax, 'interp');
    cb = colorbar(ax);
    cb.Color = [0.70 0.73 0.77];
    cb.Label.String = 'Probability';
    cb.Label.Color  = [0.70 0.73 0.77];
    caxis(ax, [0 1]);

    xlabel(ax, xl, 'Color', [0.70 0.73 0.77], 'FontSize', 8);
    ylabel(ax, yl, 'Color', [0.70 0.73 0.77], 'FontSize', 8);
    zlabel(ax, 'Output Prob.', 'Color', [0.70 0.73 0.77], 'FontSize', 8);
    zlim(ax, [0 1]);
    title(ax, ttl, 'Color', [0.90 0.93 0.95], 'FontSize', 9, 'FontWeight', 'bold');
    view(ax, -40, 30);
    grid(ax, 'on');
    ax.GridColor = [0.15 0.18 0.22];
    ax.GridAlpha = 0.5;
end

sgtitle(fig, ...
    'FuzzyShield -- 3D Rule Surface Plots (Mamdani Inference, Centroid Defuzzification)', ...
    'Color', [0.90 0.93 0.95], 'FontSize', 13, 'FontWeight', 'bold');
end


%% ── Utilities ───────────────────────────────────────────────────

function s = get_level(p)
if     p >= 0.80, s = 'CRITICAL';
elseif p >= 0.60, s = 'HIGH';
elseif p >= 0.40, s = 'MODERATE';
elseif p >= 0.20, s = 'LOW';
elseif p >= 0.05, s = 'TRACE';
else,              s = 'NONE';
end
end

function [threat_type, confidence] = get_verdict(R, T, C)
TIE_DELTA  = 0.05;
MIN_ACTIVE = 0.35;
scores     = [R, T, C];
names      = {'Ransomware', 'Trojan', 'Cryptominer'};
mx         = max(scores);

if mx < 0.10
    threat_type = 'Benign';     confidence = 'SAFE';         return;
end
if mx < 0.40
    threat_type = 'Suspicious'; confidence = 'INCONCLUSIVE'; return;
end

active = {};
for i = 1:3
    if scores(i) >= mx - TIE_DELTA && scores(i) >= MIN_ACTIVE
        active{end+1} = names{i};
    end
end
threat_type = strjoin(active, ' + ');

if mx < 0.70
    confidence = 'LIKELY THREAT';
else
    confidence = 'HIGH CONFIDENCE';
end
end

function s = center_str(str, width)
pad = max(0, floor((width - length(str)) / 2));
s   = [repmat(' ', 1, pad), str];
end

function v = iff(cond, a, b)
if cond, v = a; else, v = b; end
end

function [smoothed, new_state] = ewma_step(raw, prev_state, alpha_rise, alpha_fall)
% Asymmetric EWMA — mirrors Python EWMAFeedback.step()
%   raw, prev_state : [R T C] row vectors
%   alpha_rise=0.15 : fast rise  — new value dominates on upswing
%   alpha_fall=0.85 : slow fall  — prev value dominates on downswing
%   Formula: s = alpha * prev + (1-alpha) * raw
smoothed = zeros(1, 3);
for k = 1:3
    if raw(k) >= prev_state(k)
        a = alpha_rise;
    else
        a = alpha_fall;
    end
    smoothed(k) = a * prev_state(k) + (1.0 - a) * raw(k);
end
new_state = smoothed;
end
