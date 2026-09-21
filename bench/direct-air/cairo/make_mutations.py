#!/usr/bin/env python3
"""Produce malformed synthetic Cairo proof fixtures without changing proof dependencies."""
import argparse
import json
from pathlib import Path


def mutations(arguments):
    args = [int(x, 0) if isinstance(x, str) else x for x in arguments]
    assert args[0] == len(args) - 1, "expected one length-prefixed Span argument"
    proof = args[1:]
    output_count = proof[0]
    config = 1 + 4 * output_count + 1 + 11 * 4
    assert proof[config:config + 6] == [26, 2, 0, 35, 4, 0]
    commitments = config + 7
    assert proof[commitments] == 4
    root = commitments + 1
    cursor = root + 4 * 8

    def vector_count():
        nonlocal cursor
        count = proof[cursor]
        cursor += 1
        return count

    ood = None
    for _ in range(vector_count()):
        for _ in range(vector_count()):
            samples = vector_count()
            if samples and ood is None:
                ood = cursor
            cursor += 4 * samples
    for _ in range(vector_count()):
        hashes = vector_count()
        cursor += 8 * hashes
    queried = None
    for _ in range(vector_count()):
        count = vector_count()
        if count and queried is None:
            queried = cursor
        cursor += count
    assert ood is not None and queried is not None and cursor < len(proof)

    def changed(index, modulus):
        values = proof.copy()
        values[index] = (values[index] + 1) % modulus
        return values

    cases = {
        "pcs_pow": changed(config, 2**32),
        "lifting": changed(config + 6, 2**32),
        "preprocessed_root": changed(root, 2**32),
        "ood_value": changed(ood, 2**31 - 1),
        "queried_value": changed(queried, 2**31 - 1),
        "truncated": proof[:-1],
        "trailing": proof + [0],
        "output_count": [output_count + 1] + proof[1:1 + 4 * output_count]
                        + [0, 0, 0, 0] + proof[1 + 4 * output_count:],
    }
    if output_count:
        cases["public_output"] = changed(1, 2**31 - 1)
    return {name: [hex(len(values)), *map(hex, values)] for name, values in cases.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arguments", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    cases = mutations(json.loads(args.arguments.read_text()))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, values in cases.items():
        (args.output_dir / f"{name}.json").write_text(json.dumps(values) + "\n")
    print(json.dumps({"cases": list(cases), "count": len(cases)}))


if __name__ == "__main__":
    main()
