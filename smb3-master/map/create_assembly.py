import json
from pathlib import Path


def open_file(dir: str):
    with open(dir) as f:
        return json.load(f)


def save_file(dir: str, text: str):
    with open(dir, "w+") as f:
        f.write(text)


def convert_list_to_int(l):
    return list(map(lambda x: int(x, 16), l))


def convert_list_to_hex(l):
    return list(map(lambda x: f"${format(x, '02X')}", l))


def divide_list_by_chunks(l, chunk_size):
    return [l[i * chunk_size:(i + 1) * chunk_size] for i in range((len(l) + chunk_size - 1) // chunk_size)]


def write_strings_to_file(l, bytes_per_line: int = 16):
    s, delim = "", ", "
    for sub_l in divide_list_by_chunks(l, bytes_per_line):
        s = f"{s}\n\t.byte {delim.join(sub_l)}"
    return s


def convert_json_to_assembly(dir: str):
    return write_strings_to_file(convert_list_to_hex(convert_list_to_int(open_file(dir))))


LOCK_VADDR_HI = "lock_destroy_vaddr_hi"
LOCK_VADDR_LO = "lock_destroy_vaddr_lo"
LOCK_X = "lock_location_x"
LOCK_Y = "lock_location_y"
LOCK_REPLACE_BLOCK = "lock_replace_block"


def convert_simple_json_to_file(dir: str):
    save_file(asm_path / f"{dir}.asm", convert_json_to_assembly(json_path / f"{dir}.json"))


LOCK_PATTERNS = "lock_destroyed_patterns"
LOCK_PATTERN_LOCKUP = "lock_pattern_lockup"


def convert_patterns_to_assembly(ptn_dir: str, lockup_dir: str):
    lockups = {}
    s = ""
    for idx, (name, patterns) in enumerate(open_file(json_path / f"{ptn_dir}.json").items()):
        lockups.update({name: str(idx)})
        s = f"{s}{write_strings_to_file(patterns)}"

    save_file(asm_path / f"{ptn_dir}.asm", s)

    i = iter(list(map(lockups.get, open_file(json_path / f"{lockup_dir}.json"))))
    s = ""
    list_of_lists = [f"{int(z[0]) << 4} | {z[1]}" for z in zip(i, i)]
    for l in list_of_lists:
        s = f"{s}\n\t.byte {l}"
    save_file(asm_path / f"{lockup_dir}.asm", s)


LOCK_COMPLETE_INDEX = "map_complete_index"


def convert_lists_inside_lists_to_assembly(dir: str):
    s = ""
    list_of_lists = open_file(json_path / f"{dir}.json")
    for l in list_of_lists:
        s = f"{s}{write_strings_to_file(convert_list_to_hex(convert_list_to_int(l)))}"
    save_file(asm_path / f"{dir}.asm", s)


working_path = Path().absolute() / "map"
json_path = working_path / "json"
asm_path = working_path / "asm"


if __name__ == '__main__':
    convert_patterns_to_assembly(LOCK_PATTERNS, LOCK_PATTERN_LOCKUP)
    convert_simple_json_to_file(LOCK_VADDR_HI)
    convert_simple_json_to_file(LOCK_VADDR_LO)
    convert_simple_json_to_file(LOCK_X)
    convert_simple_json_to_file(LOCK_Y)
    convert_simple_json_to_file(LOCK_REPLACE_BLOCK)
    convert_lists_inside_lists_to_assembly(LOCK_COMPLETE_INDEX)