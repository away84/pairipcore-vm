import sys
import argparse
import json

from caterpillar.exception import StructException
from rich import print
from pairipcore import VM, context, opcode, addr_t
from pairipcore.insn import Insn, InsnFormat


def decode_string(vm: VM, data_addr: addr_t, length: int, key: bytes) -> str | None:
    result = bytearray(length)
    try:
        for i in range(length):
            result[i] = vm.context[data_addr + i] ^ key[i & 0xFF]
    except IndexError:
        return
    try:
        return result[2:].decode()
    except UnicodeDecodeError:
        pass


def address_based(
    vm: VM,
    start_addr: addr_t,
    strings: set,
    key_len: int,
    key: bytes,
) -> None:
    for i in range(start_addr, len(vm.context), 4):
        vm.context.pc = i
        if i > len(vm.context) - 4:
            break
        try:
            p_data = vm.context.addr(0x00)
            len__a = vm.context.u16(p_data)
        except StructException:
            continue
        length = (len__a ^ key_len) + 2
        if length > 1000:
            continue

        result = decode_string(vm, p_data, length, key)
        if result:
            strings.add(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Strings decoder for pairipcore.\n\n"
            "Example:\n"
            " python gvm_strings.py -in './DxeOGbdSnhqmuUs8' -opcodes ./opcodes.json -version v1"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-in", type=argparse.FileType("rb"), dest="input_file")
    parser.add_argument("-opcodes", type=argparse.FileType("r"))
    parser.add_argument(
        "-out", type=argparse.FileType("w", encoding="utf-8"), default=None
    )
    parser.add_argument("-version", default="v0")

    argv = parser.parse_args()
    opcode_func = getattr(opcode, f"decode_opcode_{argv.version}")
    entry_point_func = getattr(context, f"decode_entry_point_{argv.version}")
    if not opcode_func or not entry_point_func:
        print(
            "[bold orange]Warning:[/] Could not resolve decoder functions "
            f"of version {argv.version}"
        )
        sys.exit(1)

    doc = json.load(argv.opcodes)
    vm = VM(argv.input_file.read(), opcode_func, entry_point_func)
    _resolved_strings = set()
    for opcode_def in doc.get("opcodes", {}).values():
        if not isinstance(opcode_def, dict):
            continue

        if not opcode_def.get("decodes_array", False):
            continue

        target_opcode = opcode_def["opcode"]
        print(f"[b]Starting[/] analysis on opcode {target_opcode:#04x}...")
        print(f"[b]  >[/] Using formatid: {opcode_def['format_id']}")

        insn_format = InsnFormat.parse(opcode_def["format_id"])
        vm.context.pc = 0x08
        _potential_keys_a = {}
        _potential_keys_b = {}
        _potential_keys_c = {}
        _potential_keys_d = {}
        _potential_keys_e = {}

        def _add():
            try:
                insn = Insn(vm, insn_format)
                if insn.info.hash_data_length <= 5:
                    vars = insn_format.stack_vars + insn_format.extra_vars

                    a = _potential_keys_a.get(insn.A, 0)
                    _potential_keys_a[insn.A] = a + 1
                    if vars >= 2:
                        b = _potential_keys_b.get(insn.B, 0)
                        _potential_keys_b[insn.B] = b + 1
                    if vars >= 3:
                        c = _potential_keys_c.get(insn.C, 0)
                        _potential_keys_c[insn.C] = c + 1
                    if vars >= 4:
                        d = _potential_keys_d.get(insn.D, 0)
                        _potential_keys_c[insn.D] = d + 1
                    if vars >= 5:
                        e = _potential_keys_e.get(insn.E, 0)
                        _potential_keys_c[insn.E] = e + 1
            except Exception:
                pass

        while True:
            if vm.context.pc >= len(vm.context) - 2:
                break

            opcode = vm.current_opcode()
            if opcode == target_opcode:
                vm.context += 2
                _add()
                vm.context += len(insn_format)
            else:
                vm.context += 2

        for key_set in (
            _potential_keys_a,
            _potential_keys_b,
            _potential_keys_c,
            _potential_keys_d,
            _potential_keys_e,
        ):
            if len(key_set) == 0:
                continue

            _max = 0
            _key = None
            for key, count in key_set.items():
                if count > _max:
                    _max = count
                    _key = key
            # print(f"[b]  >[/] Running with potential key at {_key:#x}")
            strings = set()
            address_based(
                vm,
                0x08,
                strings,
                vm.context.u16(_key),
                vm.context[_key : _key + 0xFF],
            )
            # print(f"[b]    +[/] Collected {len(strings)} strings")
            if len(strings):
                _resolved_strings.update(strings)

    print("[b]Finished[/] analysis:")
    print(f"[b]  >[/] Collected {len(_resolved_strings)} strings")
    print(_resolved_strings)
