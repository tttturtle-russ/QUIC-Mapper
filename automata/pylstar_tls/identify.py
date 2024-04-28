#!/usr/bin/env python

import sys
import hashlib
import config.scenarios
import tls_args
from infer_server import TLSServerKnowledgeBase
from infer_client import TLSClientKnowledgeBase
from pylstar.Letter import Letter
from pylstar.Word import Word


class Identify:
    def __init__(self, tls_version=None, role=None, options=None):
        if role == "client":
            self.material = TLSServerKnowledgeBase(tls_version, options=options)
        elif role == "server":
            self.material = TLSClientKnowledgeBase(tls_version, options=options)
            self.material.start()
        else:
            raise Exception("Unsupported role !")
        self.role = role

    def compute_similarity(self, input_seq, expected_output, similarity):
        current_similarity = self.__initialize_dict(similarity)

        print(f"Request = {input_seq}")
        output_word = self.material.submit_word(
            Word(letters=[Letter(m) for m in input_seq])
        )
        output = [list(letter.symbols)[0] for letter in output_word.letters]
        print(f"Answer  = {output}\n\n")

        hash_output = hashlib.md5(", ".join(output).encode()).hexdigest()
        for i in range(len(expected_output)):
            curr_key = list(similarity)[i]
            hash_expected = hashlib.md5(expected_output[i].encode()).hexdigest()
            if hash_output == hash_expected:
                similarity[curr_key] += 1

        # Cleanup (stop/close) connexion
        if self.material.tls_session:
            self.material.stop_target()

        return similarity

    def run(self, distinguishers=None, list_char_filename=None):

        if not distinguishers:
            raise Exception("Distinguishers are mandatory to identify stack.")
        if not list_char_filename:
            raise Exception(
                "Characerizations filename list is mandatory to identify stack."
            )

        with open(distinguishers, "r") as fd:
            similarity = self.__initialize_dict(list_char_filename)
            list_fd_char = [open(f, "r") for f in list_char_filename]
            nb_distinguishers = 0
            while True:
                content = fd.readline()
                if not content:
                    break
                content = content.replace("\n", "")
                input_seq = content.split(", ")

                expected_output = []
                for f in list_fd_char:
                    expect_out = f.readline()
                    if not expect_out:
                        raise Exception("Expected output MUST NOT be None.")
                    expected_output.append(expect_out.replace("\n", ""))

                similarity = self.compute_similarity(
                    input_seq, expected_output, similarity
                )
                nb_distinguishers += 1

            if not nb_distinguishers:
                raise Exception("Distinguishers MUST NOT be empty.")

            # Compute the probability of similarity
            for k in similarity:
                similarity[k] = similarity[k] / nb_distinguishers

            similarity = sorted(similarity.items(), key=lambda x: x[1], reverse=True)
            max_proba = similarity[0][1]
            possible_stacks = []
            for stack, proba in similarity:
                if not possible_stacks:
                    possible_stacks.append(list_char_filename[stack])
                    continue
                if abs(max_proba - proba) <= 0.001:
                    possible_stacks.append(list_char_filename[stack])
            return (possible_stacks, max_proba)

    def __initialize_dict(self, dict_model):
        d = dict()
        for k in dict_model:
            d[k] = 0
        return d


def main():
    target = sys.argv[1]
    if target == "server":
        args = tls_args.parse_args(client_inference=False)
        role = "client"
    elif target == "client":
        args = tls_args.parse_args(client_inference=True)
        role = "server"
    else:
        raise Exception("Unknown target !")

    args.log = lambda s: None

    dirname = os.path.dirname(sys.argv[0])
    with open(
        f"{dirname}/../scenarios/{args.vocabulary}-{role}.scenario",
        "r",
        encoding="utf-8",
    ) as scenario_file:
        crypto_material_names = [name for name in args.crypto_material.iter_names()]
        scenario = config.scenarios.load_scenario(scenario_file, crypto_material_names)

    identify = Identify(
        tls_version=scenario.tls_version, role=scenario.role, options=args
    )

    list_char_filename = dict()
    for f in sys.argv[3:]:
        if ".char" not in f:
            continue
        list_char_filename[f] = f.split("/")[-1].replace(".pylstar_tls.char", "")
    results = identify.run(
        distinguishers=sys.argv[2], list_char_filename=list_char_filename
    )
    print(f"\nIdentified stack: {results[0]}")
    print(f"\nProba Similarity: {results[1]}\n")


if __name__ == "__main__":
    main()
