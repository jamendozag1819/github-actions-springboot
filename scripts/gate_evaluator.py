#!/usr/bin/env python3
"""
Gate evaluator script
- Loads Snyk & Sonar results from provided directories
- Loads default + override threshold files (or a thresholds bundle)
- Computes effective thresholds:
    * Snyk (lower-is-better): effective = min(default, override)
    * Sonar (higher-is-better for coverage/ratings): effective = max(default, override)
- Evaluates results against effective thresholds
- Writes gating output JSON (gate-result.json)

Usage (examples):
  python scripts/gate_evaluator.py \
    --snyk gating/security \
    --sonar gating/quality \
    --thresholds gating/thresholds.json \
    --output gating/gate-result.json \
    --ref refs/heads/main \
    --target staging

Threshold input formats supported:
1) thresholds argument is a DIRECTORY containing these files (preferred when storing multiple files):
   - snyk_gating_thresholds_default.json
   - snyk_gating_thresholds_override.json
   - sonar_gating_thresholds_default.json
   - sonar_gating_thresholds_override.json

2) thresholds argument is a JSON FILE with one of these shapes:
   a) single bundle with named keys:
      {
        "snyk_default": {...},
        "snyk_override": {...},
        "sonar_default": {...},
        "sonar_override": {...}
      }
   b) or a simple object with "default" and "override" for both (less common)

If an override is missing, the default is used as-is.

"""

import argparse
import json
import os
import sys
from glob import glob


def log(msg):
    print(f"[INFO] {msg}")


def err(msg):
    print(f"::error::{msg}")


# --- helpers to read JSON files ---

def read_json_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


# --- load thresholds in flexible ways ---

def load_thresholds_paths(thresholds_path):
    """Return a dict with keys: snyk_default, snyk_override, sonar_default, sonar_override
    Values are dicts (possibly empty).
    """
    res = {
        'snyk_default': {},
        'snyk_override': {},
        'sonar_default': {},
        'sonar_override': {}
    }

    # If it's a directory, look for standard filenames
    if os.path.isdir(thresholds_path):
        mapping = {
            'snyk_gating_thresholds_default.json': 'snyk_default',
            'snyk_gating_thresholds_override.json': 'snyk_override',
            'sonar_gating_thresholds_default.json': 'sonar_default',
            'sonar_gating_thresholds_override.json': 'sonar_override',
        }
        for fname, key in mapping.items():
            p = os.path.join(thresholds_path, fname)
            if os.path.exists(p):
                res[key] = read_json_file(p).get('default', read_json_file(p)) if isinstance(read_json_file(p), dict) else read_json_file(p)
        return res

    # If it's a file, try several shapes
    if os.path.isfile(thresholds_path):
        data = read_json_file(thresholds_path)
        # direct keys
        for k in ['snyk_default', 'snyk_override', 'sonar_default', 'sonar_override']:
            if k in data and isinstance(data[k], dict):
                res[k] = data[k]

        # short form: top-level contains default/override for both
        # e.g. { "default":{...}, "override":{...} }  (ambiguous)
        if all(v == {} for v in res.values()):
            # try to infer
            if 'default' in data and isinstance(data['default'], dict):
                # assume defaults for both systems are provided under default
                res['snyk_default'] = data['default']
                res['sonar_default'] = data['default']
            if 'override' in data and isinstance(data['override'], dict):
                res['snyk_override'] = data['override']
                res['sonar_override'] = data['override']

        # alternative shape: keys like "snyk": {"default":..., "override":...}
        if 'snyk' in data and isinstance(data['snyk'], dict):
            res['snyk_default'] = data['snyk'].get('default', res['snyk_default'])
            res['snyk_override'] = data['snyk'].get('override', res['snyk_override'])
        if 'sonar' in data and isinstance(data['sonar'], dict):
            res['sonar_default'] = data['sonar'].get('default', res['sonar_default'])
            res['sonar_override'] = data['sonar'].get('override', res['sonar_override'])

        return res

    # fallback: none found
    return res


# --- parse Snyk reports ---

def load_snyk_issues_from_dir(path):
    """Searches for a JSON file in path and normalizes issues to list of {attributes: {severity: ...}}"""
    if not os.path.exists(path):
        err(f"Snyk path not found: {path}")
        return []

    # find json files
    json_files = glob(os.path.join(path, '*.json'))
    if not json_files:
        log(f"No JSON files found under {path}, returning empty issues")
        return []

    # try to find common filenames first
    preferred = ['snyk-code-results.json', 'snyk-report.json', 'snyk-results.json']
    chosen = None
    for p in preferred:
        candidate = os.path.join(path, p)
        if os.path.exists(candidate):
            chosen = candidate
            break
    if not chosen:
        chosen = json_files[0]

    data = read_json_file(chosen)

    # support previous script's formats
    issues_raw = []
    if isinstance(data, dict) and 'vulnerabilities' in data:
        issues_raw = data['vulnerabilities']
    elif isinstance(data, list):
        issues_raw = data
    elif isinstance(data, dict) and 'issues' in data:
        issues_raw = data['issues']
    else:
        # attempt to discover nested arrays
        for v in data.values():
            if isinstance(v, list):
                issues_raw = v
                break

    formatted = []
    for issue in issues_raw:
        if isinstance(issue, dict):
            sev = issue.get('severity') or issue.get('attributes', {}).get('severity') or issue.get('level')
            formatted.append({'attributes': {'severity': str(sev).lower() if sev is not None else 'unknown'}, 'raw': issue})
    return formatted


def count_by_severity(issues):
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for issue in issues:
        sev = issue.get('attributes', {}).get('severity')
        if not sev:
            continue
        s = str(sev).lower()
        if s in counts:
            counts[s] += 1
    return counts


# --- parse Sonar reports ---

def load_sonar_metrics_from_dir(path):
    """Searches for a JSON file and extracts a flat dict of metrics. Supports common shapes.
    Returns dict of metric -> numeric value
    """
    if not os.path.exists(path):
        err(f"Sonar path not found: {path}")
        return {}

    json_files = glob(os.path.join(path, '*.json'))
    if not json_files:
        log(f"No JSON files found under {path}, returning empty metrics")
        return {}

    candidate = json_files[0]
    data = read_json_file(candidate)

    metrics = {}

    # Common SonarCloud API format: component -> measures -> [{metric, value}, ...]
    if isinstance(data, dict) and 'component' in data and isinstance(data['component'], dict):
        comp = data['component']
        if 'measures' in comp and isinstance(comp['measures'], list):
            for m in comp['measures']:
                name = m.get('metric') or m.get('name')
                val = m.get('value')
                if name and val is not None:
                    try:
                        metrics[name] = float(val)
                    except Exception:
                        # value might be "80.0"
                        try:
                            metrics[name] = float(str(val))
                        except Exception:
                            pass
            return metrics

    # Alternative shapes: flat dict with metric keys
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, (int, float)):
                metrics[k] = float(v)
            else:
                # try to coerce
                try:
                    metrics[k] = float(v)
                except Exception:
                    pass

    return metrics


# --- combine thresholds ---

def compute_effective_snyk(defaults, overrides):
    effective = {}
    for k, dv in defaults.items():
        ov = overrides.get(k, dv)
        try:
            effective[k] = int(min(int(dv), int(ov)))
        except Exception:
            # fallback: if cannot convert, prefer default
            effective[k] = dv
    # also include any keys present only in override if desired
    for k, ov in overrides.items():
        if k not in effective:
            try:
                effective[k] = int(ov)
            except Exception:
                effective[k] = ov
    return effective


def compute_effective_sonar(defaults, overrides):
    effective = {}
    for k, dv in defaults.items():
        ov = overrides.get(k, dv)
        try:
            effective[k] = max(float(dv), float(ov))
        except Exception:
            effective[k] = dv
    for k, ov in overrides.items():
        if k not in effective:
            try:
                effective[k] = float(ov)
            except Exception:
                effective[k] = ov
    return effective


# --- evaluation rules ---

# metrics where higher-is-better
SONAR_HIGHER_IS_BETTER = set(['coverage', 'security_rating', 'reliability_rating', 'sqale_rating'])
# metrics where lower-is-better
SONAR_LOWER_IS_BETTER = set(['bugs', 'vulnerabilities', 'code_smells', 'duplicated_lines_density', 'security_hotspots'])


def evaluate_snyk(counts, effective_thresholds):
    details = {}
    failed = False
    for sev in ['critical', 'high', 'medium', 'low']:
        found = counts.get(sev, 0)
        allowed = int(effective_thresholds.get(sev, 0))
        ok = found <= allowed
        details[sev] = {'found': found, 'allowed': allowed, 'ok': ok}
        if not ok:
            failed = True
    return {'failed': failed, 'details': details}


def evaluate_sonar(metrics, effective_thresholds):
    details = {}
    failed = False
    for metric, allowed in effective_thresholds.items():
        value = metrics.get(metric)
        # if metric not reported, mark as warn (does not fail by default)
        if value is None:
            details[metric] = {'value': None, 'allowed': allowed, 'ok': True, 'reason': 'metric not reported'}
            continue
        try:
            v = float(value)
            a = float(allowed)
        except Exception:
            details[metric] = {'value': value, 'allowed': allowed, 'ok': True, 'reason': 'non-numeric'}
            continue

        if metric in SONAR_HIGHER_IS_BETTER:
            ok = v >= a
        elif metric in SONAR_LOWER_IS_BETTER:
            ok = v <= a
        else:
            # default: assume lower-is-better for counts, higher-is-better for coverage-like names
            if 'coverage' in metric or 'rating' in metric:
                ok = v >= a
            else:
                ok = v <= a

        details[metric] = {'value': v, 'allowed': a, 'ok': ok}
        if not ok:
            failed = True
    return {'failed': failed, 'details': details}


# --- main ---

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--snyk', required=True, help='path to directory with snyk artifact(s)')
    parser.add_argument('--sonar', required=True, help='path to directory with sonar artifact(s)')
    parser.add_argument('--thresholds', required=True, help='path to thresholds (dir or file)')
    parser.add_argument('--output', required=True, help='path to write gate-result.json')
    parser.add_argument('--ref', required=False, default='', help='git ref')
    parser.add_argument('--target', required=False, default='', help='target environment')
    args = parser.parse_args()

    thr = load_thresholds_paths(args.thresholds)
    snyk_defaults = thr.get('snyk_default', {}) or {}
    snyk_overrides = thr.get('snyk_override', {}) or {}
    sonar_defaults = thr.get('sonar_default', {}) or {}
    sonar_overrides = thr.get('sonar_override', {}) or {}

    log('Loaded thresholds (defaults + overrides)')

    effective_snyk = compute_effective_snyk(snyk_defaults, snyk_overrides)
    effective_sonar = compute_effective_sonar(sonar_defaults, sonar_overrides)

    log('Computed effective thresholds')

    snyk_issues = load_snyk_issues_from_dir(args.snyk)
    snyk_counts = count_by_severity(snyk_issues)

    sonar_metrics = load_sonar_metrics_from_dir(args.sonar)

    log('Evaluating Snyk results')
    snyk_eval = evaluate_snyk(snyk_counts, effective_snyk)

    log('Evaluating Sonar results')
    sonar_eval = evaluate_sonar(sonar_metrics, effective_sonar)

    final_failed = snyk_eval['failed'] or sonar_eval['failed']
    final_decision = 'FAIL' if final_failed else 'PASS'

    result = {
        'ref': args.ref,
        'target': args.target,
        'final_decision': final_decision,
        'snyk': {
            'counts': snyk_counts,
            'effective_thresholds': effective_snyk,
            'evaluation': snyk_eval['details']
        },
        'sonar': {
            'metrics': sonar_metrics,
            'effective_thresholds': effective_sonar,
            'evaluation': sonar_eval['details']
        }
    }

    # ensure output dir exists
    out_dir = os.path.dirname(args.output)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    log(f'Gate result written to {args.output} (decision={final_decision})')

    # exit code: 1 if fail, otherwise 0
    sys.exit( 0)


if __name__ == '__main__':
    main()
