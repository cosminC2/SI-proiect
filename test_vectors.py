
from typing import List
from itertools import starmap
import re

def read_test_vector(option: str) -> List[tuple[bytes, bytes, bytes]]:
    pattern = r"KEY = ([a-z0-9]+)\nPLAINTEXT = ([a-z0-9]+)\nCIPHERTEXT = ([a-z0-9]+)"
    match option:
        case '128':
            with open("test_vectors/ECBKeySbox128.rsp", "r") as file:
                content = file.read()
                matches = re.findall(pattern, content, flags=re.M|re.U)
                return list(starmap(lambda x, y, z : (bytes.fromhex(x), bytes.fromhex(y), bytes.fromhex(z)), matches))
        case '192':
            with open("test_vectors/ECBKeySbox192.rsp", "r") as file:
                content = file.read()
                matches = re.findall(pattern, content, flags=re.M|re.U)
                return list(starmap(lambda x, y, z : (bytes.fromhex(x), bytes.fromhex(y), bytes.fromhex(z)), matches))
        case '256':
            with open("test_vectors/ECBKeySbox256.rsp", "r") as file:
                content = file.read()
                matches = re.findall(pattern, content, flags=re.M|re.U)
                return list(starmap(lambda x, y, z : (bytes.fromhex(x), bytes.fromhex(y), bytes.fromhex(z)), matches))
        case _:
            return []