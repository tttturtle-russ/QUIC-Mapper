from typing import List, Set, Tuple, Dict, TextIO
import configparser


def rewrite_msgs(msgs: List[str], pattern: str, words: List[str]) -> List[str]:
    result = []
    for msg in msgs:
        if pattern in msg:
            for word in words:
                result.append(msg.replace(pattern, word))
        else:
            result.append(msg)
    return result


def set_of_str(msgs_str: str) -> Set[str]:
    if msgs_str:
        return set(msgs_str.split("+"))
    return set()


class ScenarioError(BaseException):
    pass


class QUICScenario:
    def __init__(self,
                 scenario_description: configparser.ConfigParser
                 ):
        if (
                "general" not in scenario_description.sections()
                or "name" not in scenario_description["general"]
                or "role" not in scenario_description["general"]
        ):
            raise ScenarioError(
                "Missing name or role in the general section"
            )
        self.scenario_description = scenario_description
        self.input_vocabulary: List[str] = []
        self.register_input_vocabulary()

    @property
    def name(self) -> str:
        return self.scenario_description["general"]["name"]

    @property
    def role(self) -> str:
        return self.scenario_description["general"]["role"]

    def register_input_vocabulary(self):
        if "input_vocabulary" not in self.scenario_description["general"]:
            raise ScenarioError("Missing input_vocabulary in the general section")

        self.input_vocabulary = self.get_list("general", "input_vocabulary")

    def get_list(self, section: str, parameter: str) -> List[str]:
        try:
            raw_msgs: str = self.scenario_description[section][parameter]
            return [msg.strip() for msg in raw_msgs.split(",")]
        except KeyError:
            return []

    def check_path_consistency(self, path: List[str]):
        for msg in path:
            if msg not in self.input_vocabulary:
                raise ScenarioError(f'Unknown message "{msg}" in path "{path}"')


class Scenario:
    def __init__(
            self,
            scenario_description: configparser.ConfigParser,
            crypto_material_names: List[str],
    ):
        if (
                "general" not in scenario_description.sections()
                or "name" not in scenario_description["general"]
                or "role" not in scenario_description["general"]
                or "tls_version" not in scenario_description["general"]
        ):
            raise ScenarioError(
                "Missing name, role or tls_version in the general section"
            )

        self.scenario_description = scenario_description
        self.check_general_parameters()

        self.crypto_material_names = crypto_material_names

        self.input_vocabulary: List[str] = []
        self.register_input_vocabulary()

        self.interesting_paths: List[List[str]] = []
        self.register_interesting_paths()
        self.happy_paths: List[List[Tuple[str, Set[str]]]] = []
        self.register_happy_paths()

    @property
    def name(self) -> str:
        return self.scenario_description["general"]["name"]

    @property
    def role(self) -> str:
        return self.scenario_description["general"]["role"]

    @property
    def tls_version(self) -> str:
        return self.scenario_description["general"]["tls_version"]

    def check_general_parameters(self):
        if self.role not in ("client", "server"):
            raise ScenarioError(f"Invalid general.role value ({self.role})")

        if self.tls_version not in ("tls10", "tls11", "tls12", "tls13"):
            raise ScenarioError(f"Invalid general.role value ({self.tls_version})")

    def register_input_vocabulary(self):
        if "input_vocabulary" not in self.scenario_description["general"]:
            raise ScenarioError("Missing input_vocabulary in the general section")

        msgs: List[str] = self.get_list("general", "input_vocabulary")
        self.input_vocabulary = rewrite_msgs(
            msgs, "{crypto_material_name}", self.crypto_material_names
        )

    def get_list(self, section: str, parameter: str) -> List[str]:
        try:
            raw_msgs: str = self.scenario_description[section][parameter]
            return [msg.strip() for msg in raw_msgs.split(",")]
        except KeyError:
            return []

    def register_interesting_paths(self):
        allowed_parameters: Dict[str, Tuple[str, List[str]]] = {}
        allowed_parameters["crypto_material_name"] = (
            "{crypto_material_name}",
            self.crypto_material_names,
        )
        for name in self.get_list("general", "interesting_paths"):
            self.register_interesting_path(name.strip(), allowed_parameters)

    def register_interesting_path(
            self, path_name: str, allowed_parameters: Dict[str, Tuple[str, List[str]]]
    ):
        msgs: List[str] = self.get_list(path_name, "path")
        if not msgs:
            raise ScenarioError(f"Empty path ({path_name})")

        parameter: str = self.scenario_description[path_name].get("parameter", "")
        if not parameter:
            self.check_path_consistency(msgs)
            self.interesting_paths.append(msgs)
        elif parameter in allowed_parameters:
            pattern, parameter_values = allowed_parameters[parameter]
            for name in parameter_values:
                next_interesting_path = rewrite_msgs(msgs, pattern, [name])
                self.check_path_consistency(next_interesting_path)
                self.interesting_paths.append(next_interesting_path)
        else:
            raise ScenarioError(f"Unsupported path parameter ({parameter})")

    def check_path_consistency(self, path: List[str]):
        for msg in path:
            if msg not in self.input_vocabulary:
                raise ScenarioError(f'Unknown message "{msg}" in path "{path}"')

    def register_happy_paths(self):
        for name in self.get_list("general", "happy_paths"):
            self.register_interesting_path(name.strip(), {})
            self.register_happy_path(name.strip())

    def register_happy_path(self, path_name: str):
        sent_msgs = self.get_list(path_name, "path")
        received_str = self.get_list(path_name, "answers")
        received_msgs = [set_of_str(msgs_str) for msgs_str in received_str]
        if len(sent_msgs) != len(received_msgs):
            raise ScenarioError("Unbalanced happy path")
        self.happy_paths.append(list(zip(sent_msgs, received_msgs)))


def load_scenario(input_file: TextIO):
    config = configparser.ConfigParser()
    try:
        config.read_file(input_file)
    except configparser.Error as parsing_err:
        raise ScenarioError("Invalid config file") from parsing_err
    return QUICScenario(config)
