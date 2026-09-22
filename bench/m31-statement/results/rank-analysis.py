#!/usr/bin/env python3
"""Rank analysis for the L2-lemma empirical probe (M31 statement).

Consumes rank-substrate.json (from --dump-rank-substrate) and computes, in
exact arithmetic mod P (M31):
  1. the functional count per observation point,
  2. dim span(W): the rank of the position-family of weight vectors,
  3. dim span(M): the rank of the valid-row expansion family (joint and per
     column),
  4. the secant-family rank over sampled statement pairs,
  5. the pad-contribution span vs the secant family: empirical containment
     for B in {1, 2, 4, 8, 16, 40}.

Measurement infrastructure; no privacy claim.
"""
import json
import sys

import numpy as np

P = 2**31 - 1


def rank_modp(mat, ncols_cap=None):
    """Rank of mat (n x m) over GF(P) via Gaussian elimination. mat: int64."""
    a = mat.copy() % P
    n, m = a.shape
    if ncols_cap is not None:
        a = a[:, :ncols_cap]
        m = a.shape[1]
    r = 0
    for c in range(m):
        if r >= n:
            break
        piv = None
        col = a[r:, c] % P
        nz = np.nonzero(col)[0]
        if len(nz) == 0:
            continue
        piv = r + nz[0]
        if piv != r:
            a[[r, piv]] = a[[piv, r]]
        inv = pow(int(a[r, c]), P - 2, P)
        a[r] = (a[r] * inv) % P
        rows = [i for i in range(n) if i != r]
        factors = a[rows, c].copy()
        a[rows] = (a[rows] - factors[:, None] * a[r][None, :]) % P
        r += 1
    return r


def main(path):
    print(f"loading {path} ...", flush=True)
    d = json.load(open(path))
    rows = d["rows"]
    ncols = d["columns"]
    weights = d["weights"]  # [t][i] -> [4]
    nt = len(weights)

    # 1. functional count per point
    kinds = []
    for t in range(nt):
        chans = [k for k in range(4) if any(w[k] != 0 for w in weights[t])]
        kinds.append(len(chans))
    d_obs_per_col = sum(kinds)
    print(f"points: {nt}; functional channels per point: {kinds}")
    print(f"D_obs per column = {d_obs_per_col}; joint over {ncols} columns = {d_obs_per_col * ncols:,}")

    # 2. dim span(W): positions i -> weight vector in (t,k)-space
    W = np.array([[weights[t][i][k] for t in range(nt) for k in range(4)] for i in range(rows)], dtype=np.int64)
    dimW = rank_modp(W)
    print(f"dim span(W) = {dimW} of {W.shape[1]} (positions: {rows})")

    # 3. dim span(M): valid-row value vectors in the 1172-dim column space
    exp = d["expansion_samples"]
    print(f"expansion samples: {len(exp)}", flush=True)
    Mmat = np.stack([np.array(s["values"], dtype=np.int64) for s in exp])
    dimM = rank_modp(Mmat)
    print(f"dim span(M) = {dimM} of {Mmat.shape[1]} (samples: {len(exp)})  <-- DECISIVE for the lemma precondition (need >= 68)")

    # 4. secant family rank
    sec = d["secant_samples"]
    Smat = np.stack([
        np.array([v for t in range(nt) for j in range(ncols) for v in s["delta"][t][j]], dtype=np.int64)
        for s in sec
    ])
    dimS = rank_modp(Smat)
    print(f"secant samples: {len(sec)}; flattened rank = {dimS} of {Smat.shape[1]:,} (sample-limited)")
    # The governing quantity: per-sample MATRIX rank of the delta reshaped to
    # (t,k) x j  (96 x 1172). The pad budget must cover this rank with
    # manifold-valid rank-1 terms.
    matrix_ranks = []
    for s in sec:
        arr = np.array([v for t in range(nt) for j in range(ncols) for v in s["delta"][t][j]], dtype=np.int64)
        mat = arr.reshape(nt, ncols, 4).transpose(0, 2, 1).reshape(nt * 4, ncols)
        matrix_ranks.append(rank_modp(mat))
    print(f"per-sample matrix rank (96 x 1172): {matrix_ranks}")

    # 5. pad contributions vs secant containment
    pads = d["pads"]
    exp_by_pos = {}
    for s in exp:
        exp_by_pos[s["position"]] = s
    contribs = []
    for s in exp:
        pos = s["position"]
        vec = np.zeros(nt * 4 * ncols, dtype=np.int64)
        for t in range(nt):
            for k in range(4):
                w = weights[t][pos][k]
                if w == 0:
                    continue
                col = np.array(s["values"], dtype=np.int64)
                block = (col * w) % P
                vec[(t * 4 + k) * ncols:(t * 4 + k) * ncols + ncols] = block
        contribs.append(vec)
    Cmat = np.stack(contribs)
    dimC = rank_modp(Cmat)
    print(f"pad contributions: {len(contribs)}; span rank = {dimC}")
    # 6. row-space containment: is the trace-delta's row space inside M-span?
    for s in d.get("secant_rows_samples", []):
        DR = np.array(s["delta_rows"], dtype=np.int64)
        r_rows = rank_modp(DR)
        union = np.vstack([Mmat, DR])
        r_union = rank_modp(union)
        print(f"pair {s['pair']}: rank(delta_rows) = {r_rows}; rank(M-span + delta_rows) = {r_union}; "
              f"row space contained in M-span: {r_union == dimM}  <-- DECISIVE for ideal containment")
    for B in [1, 2, 4, 8, 16, 40]:
        rng = np.random.default_rng(B)
        idx = list(rng.choice(len(contribs), size=min(B, len(contribs)), replace=False))
        sub = Cmat[idx]
        union = np.vstack([sub, Smat])
        r_sub = rank_modp(sub)
        r_union = rank_modp(union)
        contained = r_union == r_sub
        print(f"B={B}: pad-span rank {r_sub}, union-with-secant rank {r_union}, secant contained: {contained}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "rank-substrate.json")
