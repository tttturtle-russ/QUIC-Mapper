import sys
from automata.automata import load_automaton_from_file


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage : python bdist_compute.py file.automaton ")
    result = load_automaton_from_file(sys.argv[1]).compute_bdist()
    print(f"Distinguishing Bound = {result[0]}")
    print(f"State pairs reaching the bound = {result[1]}")
