#!/usr/bin/env python

import sys
from automata.automata import load_automaton_from_file, fingerprint_automata


def fingerprint():
    """Show message sequences to distinguish two automata"""
    if len(sys.argv) < 4:
        raise Exception("Usage: fingerprint.py output_dir automaton1 automaton2 ...")

    list_automata_filename = sys.argv[2:]
    output_dir = sys.argv[1]

    automata = [load_automaton_from_file(arg) for arg in list_automata_filename]
    fingerprints = fingerprint_automata(automata)

    print(f"Fingerprinting requires {len(fingerprints)} sequences:")
    with open(f"{output_dir}/distinguishers.txt", "w") as distinguishers:
        for (sequence, _) in fingerprints:
            print(f"  - {sequence}")
            distinguishers.write(f"{', '.join(sequence)}\n")

    for i in range(len(list_automata_filename)):
        stackname = list_automata_filename[i].split("/")[-1]
        with open(f"{output_dir}/{stackname}.char", "w") as char:
            for _, output_list in fingerprints:
                update_output = ", ".join(
                    ["+".join(output) for output in output_list[i]]
                )
                char.write(f"{update_output}\n")


fingerprint()
