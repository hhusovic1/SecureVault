#!/usr/bin/env python3
"""
Crta grafove iz CSV-a koji izvozi /api/benchmark/export?format=csv.

Proizvodi (u tekućem direktoriju):
  - throughput_vs_size.png  — propusnost (MB/s) vs. veličina podataka, log-x,
                              po simetričnom algoritmu (operacija ENCRYPT)
  - asymmetric_keygen.png   — vrijeme generisanja ključa (ms) po algoritmu/parametru

Pokretanje:
    pip install -r requirements.txt
    python plot_benchmarks.py benchmark.csv
"""
import csv
import sys
from collections import defaultdict

import matplotlib.pyplot as plt


def load(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def plot_symmetric_throughput(rows):
    # {algorithm: [(dataSizeKB, throughputMBs), ...]} za ENCRYPT
    series = defaultdict(list)
    for r in rows:
        if r["category"] == "SYMMETRIC" and r["operation"] == "ENCRYPT" and r["throughputMBs"]:
            series[r["algorithm"]].append((int(r["dataSizeKB"]), float(r["throughputMBs"])))
    if not series:
        print("[i] Nema simetričnih podataka za graf propusnosti.")
        return

    plt.figure(figsize=(8, 5))
    for alg, pts in sorted(series.items()):
        pts.sort()
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        plt.plot(xs, ys, marker="o", label=alg)
    plt.xscale("log")
    plt.xlabel("Veličina podataka (KB, log skala)")
    plt.ylabel("Propusnost (MB/s)")
    plt.title("Propusnost enkripcije po algoritmu i veličini podataka")
    plt.legend()
    plt.grid(True, which="both", ls=":")
    plt.tight_layout()
    plt.savefig("throughput_vs_size.png", dpi=150)
    print("[✓] throughput_vs_size.png")


def plot_asymmetric_keygen(rows):
    labels, values = [], []
    for r in rows:
        if r["category"] == "ASYMMETRIC" and r["operation"] == "KEYGEN":
            labels.append(f"{r['algorithm']}\n{r['parameter']}")
            values.append(float(r["avgMs"]))
    if not labels:
        print("[i] Nema asimetričnih KEYGEN podataka za graf.")
        return

    plt.figure(figsize=(9, 5))
    plt.bar(labels, values, color="#3b6ea5")
    plt.ylabel("Vrijeme generisanja ključa (ms)")
    plt.title("Vrijeme generisanja ključa po algoritmu i parametru")
    plt.yscale("log")
    plt.grid(True, axis="y", ls=":")
    plt.tight_layout()
    plt.savefig("asymmetric_keygen.png", dpi=150)
    print("[✓] asymmetric_keygen.png")


def main():
    if len(sys.argv) != 2:
        print("Upotreba: python plot_benchmarks.py benchmark.csv", file=sys.stderr)
        sys.exit(2)
    rows = load(sys.argv[1])
    plot_symmetric_throughput(rows)
    plot_asymmetric_keygen(rows)


if __name__ == "__main__":
    main()
