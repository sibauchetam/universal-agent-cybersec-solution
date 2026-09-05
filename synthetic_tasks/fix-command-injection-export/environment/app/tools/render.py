#!/usr/bin/env python3
"""Benign rendering tool used by the report exporter.

Usage: render.py --report ID --format F --out PATH
Exits with code 2 if the report id is unknown.
"""
import argparse

REPORTS = {
    "weekly-42": "Weekly digest #42: builds green, queue depth 3.",
    "q2-financials": "Q2 financials: revenue up, churn flat.",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--format", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.report not in REPORTS:
        print(f"unknown report: {args.report}")
        return 2
    with open(args.out, "wb") as fh:
        fh.write(f"RENDER-OK-{args.report}\n".encode())
        fh.write(REPORTS[args.report].encode())
        fh.write(f"\n(format={args.format})\n".encode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
