"""This module contains representation classes for Solidity files, contracts
and source mappings."""
from typing import Dict, Set
import logging
from typing import Union

import mythril.laser.ethereum.util as helper
from mythril.ethereum.evmcontract import EVMContract
from mythril.ethereum.util import get_solc_json
from mythril.exceptions import NotMatchingOnchainCodeError, NoContractFoundError
log = logging.getLogger(__name__)


class SourceMapping:
    def __init__(self, solidity_file_idx, offset, length, lineno, mapping):
        """Representation of a source mapping for a Solidity file."""

        self.solidity_file_idx = solidity_file_idx
        self.offset = offset
        self.length = length
        self.lineno = lineno
        self.solc_mapping = mapping


class SolidityFile:
    """Representation of a file containing Solidity code."""

    def __init__(self, filename: str, data: str, full_contract_src_maps: Set[str]):
        """
        Metadata class containing data regarding a specific solidity file
        :param filename: The filename of the solidity file
        :param data: The code of the solidity file
        :param full_contract_src_maps: The set of contract source mappings of all the contracts in the file
        """
        self.filename = filename
        self.data = data
        self.full_contract_src_maps = full_contract_src_maps


class SourceCodeInfo:
    def __init__(self, filename, lineno, code, mapping):
        """Metadata class containing a code reference for a specific file."""

        self.filename = filename
        self.lineno = lineno
        self.code = code
        self.solc_mapping = mapping


def get_contracts_from_file(input_file, solc_settings_json=None, solc_binary="solc"):
    """

    :param input_file:
    :param solc_settings_json:
    :param solc_binary:
    """
    data = get_solc_json(
        input_file, solc_settings_json=solc_settings_json, solc_binary=solc_binary
    )

    try:
        contract_names = data["contracts"][input_file].keys()
    except KeyError:
        raise NoContractFoundError

    for contract_name in contract_names:
        if len(
            data["contracts"][input_file][contract_name]["evm"]["deployedBytecode"][
                "object"
            ]
        ):
            yield SolidityContract(
                input_file=input_file,
                name=contract_name,
                solc_settings_json=solc_settings_json,
                solc_binary=solc_binary,
            )

def get_contracts_from_json(compiled_json, input_file, input_file_contents, onchain_code=None, onchain_name=None):
    """

    :param input_file:
    :param solc_settings_json:
    :param solc_binary:
    """
    data = compiled_json
    
    try:
        contract_names = data["contracts"][input_file].keys()
    except KeyError:
        raise NoContractFoundError

    for contract_name in contract_names:
        if len(
            data["contracts"][input_file][contract_name]["evm"]["deployedBytecode"][
                "object"
            ]
        ):
            # print(onchain_name)
            # print("###################################################")
            # print(contract_name)
            # print("###################################################")
            # print(onchain_code)
            # print("###################################################")
            # print(data["contracts"][input_file][contract_name]["evm"]["deployedBytecode"][
            #     "object"
            # ])
            
            yield SolidityContract(
                input_file=input_file,
                name=contract_name,
                compiled_json=data,
                input_file_contents=input_file_contents,
                onchain_code=onchain_code if onchain_name == contract_name else None
            )

class SolidityContract(EVMContract):
    """Representation of a Solidity contract."""

    def __init__(
        self, input_file=None, name=None, solc_settings_json=None, solc_binary="solc", compiled_json=None, input_file_contents=None, onchain_code=None
    ):
        if (compiled_json):
            data = compiled_json
            self.solc_indices = self.get_solc_indices(data, input_file_contents)
            self.id_to_file_map = self.get_id_to_file_map(data)
        else:
            data = get_solc_json(
                input_file, solc_settings_json=solc_settings_json, solc_binary=solc_binary
            )
            self.solc_indices = self.get_solc_indices(data)
            self.id_to_file_map = self.get_id_to_file_map(data)

        self.solc_json = data
        self.input_file = input_file
        has_contract = False

        # If a contract name has been specified, find the bytecode of that specific contract
        srcmap_constructor = []
        srcmap = []
        if name:
            contract = data["contracts"][input_file][name]
            if len(contract["evm"]["deployedBytecode"]["object"]):
                code = contract["evm"]["deployedBytecode"]["object"]
                creation_code = contract["evm"]["bytecode"]["object"]
                srcmap = contract["evm"]["deployedBytecode"]["sourceMap"].split(";")
                srcmap_constructor = contract["evm"]["bytecode"]["sourceMap"].split(";")
                has_contract = True

        # If no contract name is specified, get the last bytecode entry for the input file

        else:
            for contract_name, contract in sorted(
                data["contracts"][input_file].items()
            ):
                if len(contract["evm"]["deployedBytecode"]["object"]):
                    name = contract_name
                    code = contract["evm"]["deployedBytecode"]["object"]
                    creation_code = contract["evm"]["bytecode"]["object"]
                    srcmap = contract["evm"]["deployedBytecode"]["sourceMap"].split(";")
                    srcmap_constructor = contract["evm"]["bytecode"]["sourceMap"].split(
                        ";"
                    )
                    has_contract = True

        if not has_contract:
            raise NoContractFoundError

        self.mappings = []

        self.constructor_mappings = []

        self._get_solc_mappings(srcmap)
        self._get_solc_mappings(srcmap_constructor, constructor=True)
        
        # print(self.trim_metadata(onchain_code[2:]))
        # print('######################')
        # print('######################')
        # print('######################')
        # print('######################')
        # print('######################')
        # print(self.trim_metadata(code))

        if (onchain_code is not None and self.trim_metadata(onchain_code[2:]) != self.trim_metadata(code)):
            raise NotMatchingOnchainCodeError(f"Onchain code does not match compiled code. Please check if the contract address is correct, and you are executing the correct contract that was deployed.")
        
        super().__init__(code, creation_code, name=name)

    @staticmethod
    def get_sources(indices_data: Dict, source_data: Dict) -> None:
        """
        Get source indices mapping
        """
        if "generatedSources" not in source_data:
            return
        sources = source_data["generatedSources"]
        for source in sources:
            full_contract_src_maps = SolidityContract.get_full_contract_src_maps(
                source["ast"]
            )
            indices_data[source["id"]] = SolidityFile(
                source["name"], source["contents"], full_contract_src_maps
            )

    @staticmethod
    def get_solc_indices(data: Dict, input_file_contents: str = None) -> Dict:
        """
        Returns solc file indices
        """
        indices: Dict = {}
        for contract_data in data["contracts"].values():
            for source_data in contract_data.values():
                SolidityContract.get_sources(indices, source_data["evm"]["bytecode"])
                SolidityContract.get_sources(
                    indices, source_data["evm"]["deployedBytecode"]
                )
                
        for source in data["sources"].values():
            full_contract_src_maps = SolidityContract.get_full_contract_src_maps(
                source["ast"]
            )
            if input_file_contents:
                code = input_file_contents
                indices[source["id"]] = SolidityFile(
                    source["ast"]["absolutePath"], code, full_contract_src_maps
                )
            else:
                with open(source["ast"]["absolutePath"]) as f:
                    code = f.read()
                    indices[source["id"]] = SolidityFile(
                        source["ast"]["absolutePath"], code, full_contract_src_maps
                    )
        return indices

    @staticmethod
    def trim_metadata(code: str = None) -> str:
        """
        Returns bytecode without metadata at the end
        """
        metadata_size = int(code[-4:], 16) * 2 + 4
        return code[:-metadata_size]

    @staticmethod
    def get_id_to_file_map(data: Dict) -> Dict:
        """
        Returns solc id to file map
        """
        id_to_file_map: Dict = {}
        for filename in data["sources"].keys():
            id_to_file_map[data["sources"][filename]["id"]] = filename
        return id_to_file_map

    @staticmethod
    def get_full_contract_src_maps(ast: Dict) -> Set[str]:
        """
        Takes a solc AST and gets the src mappings for all the contracts defined in the top level of the ast
        :param ast: AST of the contract
        :return: The source maps
        """
        source_maps = set()
        if ast["nodeType"] == "SourceUnit":
            for child in ast["nodes"]:
                if child.get("contractKind"):
                    source_maps.add(child["src"])
        elif ast["nodeType"] == "YulBlock":
            for child in ast["statements"]:
                source_maps.add(child["src"])

        return source_maps

    def get_source_info(self, address, constructor=False):
        """

        :param address:
        :param constructor:
        :return:
        """
        disassembly = self.creation_disassembly if constructor else self.disassembly
        mappings = self.constructor_mappings if constructor else self.mappings
        index = helper.get_instruction_index(disassembly.instruction_list, address)
        file_index = mappings[index].solidity_file_idx

        if file_index == -1:
            # If issue is detected in an internal file
            return None

        solidity_file = self.solc_indices[file_index]
        filename = solidity_file.filename

        offset = mappings[index].offset
        length = mappings[index].length

        code = solidity_file.data.encode("utf-8")[offset : offset + length].decode(
            "utf-8", errors="ignore"
        )
        lineno = mappings[index].lineno
        return SourceCodeInfo(filename, lineno, code, mappings[index].solc_mapping)

    def get_source_mapping(self, address, constructor=False):
        """

        :param address:
        :param constructor:
        :return:
        """
        disassembly = self.creation_disassembly if constructor else self.disassembly
        mappings = self.constructor_mappings if constructor else self.mappings
        index = helper.get_instruction_index(disassembly.instruction_list, address)
        return mappings[index]

    def _is_autogenerated_code(self, offset: int, length: int, file_index: int) -> bool:
        """
        Checks whether the code is autogenerated or not
        :param offset: offset of the code
        :param length: length of the code
        :param file_index: file the code corresponds to
        :return: True if the code is internally generated, else false
        """

        if file_index == -1:
            return True
        # Handle the common code src map for the entire code.
        if (
            "{}:{}:{}".format(offset, length, file_index)
            in self.solc_indices[file_index].full_contract_src_maps
        ):
            return True

        return False

    def has_source(self, file_index: int) -> bool:
        return file_index in self.id_to_file_map

    def _get_solc_mappings(self, srcmap, constructor=False):
        """

        :param srcmap:
        :param constructor:
        """
        mappings = self.constructor_mappings if constructor else self.mappings
        prev_mapping: Union[SourceMapping, None] = None
        for item in srcmap:
            if item == "":
                mappings.append(prev_mapping)
                continue
            
            mapping = item.split(":")

            if len(mapping) > 0 and len(mapping[0]) > 0:
                offset = int(mapping[0])
            else:
                offset = prev_mapping.offset

            if len(mapping) > 1 and len(mapping[1]) > 0:
                length = int(mapping[1])
            else:
                length = prev_mapping.length

            if len(mapping) > 2 and len(mapping[2]) > 0:
                idx = int(mapping[2])
            else:
                idx = prev_mapping.solidity_file_idx

            if self._is_autogenerated_code(offset, length, idx):
                lineno = None
            else:
                lineno = (
                    self.solc_indices[idx]
                    .data.encode("utf-8")[0:offset]
                    .count("\n".encode("utf-8"))
                    + 1
                )
            new_mapping = SourceMapping(idx, offset, length, lineno, item)
            prev_mapping = new_mapping
            mappings.append(new_mapping)
