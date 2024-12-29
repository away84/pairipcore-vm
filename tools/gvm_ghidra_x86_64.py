# THis is just a naive implementation of the opcode scanner
import argparse
import dataclasses
import sys
import os
import json
import re
import pathlib
import tree_sitter_c

from rich import print
from rich.console import Console
from tree_sitter import Node, Parser, Language, Tree

console = Console()


# -----------------------------------------------------------------------------
# Classes
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class OpcodeHandler:
    opcode: int
    format_id: str | None
    addresses: list[int] | None = None
    code_line: int | None = None
    code_file: str | None = None
    decodes_array: bool = False


@dataclasses.dataclass
class OpcodeDef:
    vm_dispatch_0: int = -1
    vm_dispatch_1: int = -1
    vm_dispatch_2: int = -1
    vm_decode_array: int = -1
    opcodes: dict[int, OpcodeHandler] = dataclasses.field(default_factory=dict)
    default_cases: list[int] = dataclasses.field(default_factory=list)

    def __getitem__(self, key) -> OpcodeHandler:
        return self.opcodes[key]

    def __setitem__(self, key, value):
        self.opcodes[key] = value


# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
C = Language(tree_sitter_c.language(), "c")
LEFT = 0
RIGHT = 1

# -----------------------------------------------------------------------------
# Queries
# -----------------------------------------------------------------------------
# Attempts to find all integer assignments in the function prologue. We can
# simply apply this query and filter out any results that are defined after
# the first function call.
tsq_state_assignment = C.query("""\
(
    (assignment_expression
        left: (identifier)
        right: (number_literal)
    ) @assign
)
""")

# Necessary to find the first function call before the state machine begins
tsq_func_assignment = C.query("""\
(assignment_expression
    left: (identifier)
    right: (call_expression)) @fn_assign
""")

# used to find all handlers
tsq_handler_query = C.query("""\
(assignment_expression
    left: (identifier)
    right: (pointer_expression)) @handler
""")

# Lax query to find all assignments around the handler code
tsq_assignment_query = C.query("""\
(assignment_expression
    left: (identifier)) @handler
""")

# Tracks any assignments of the first function parameter
tsq_vm_assignment = C.query("""\
((assignment_expression
    left: (identifier) @target
    right: (identifier) @name ) (#eq? @name "param_1")) @node
""")


# -----------------------------------------------------------------------------
# Tree-Sitter Functions
# -----------------------------------------------------------------------------
def ts_get_type_pattern(var: str) -> re.Pattern:
    return re.compile(rf"\s*\w*\s=\s*.*\s*.*\*\((\w*)\s*[(]?\**[)]?\).*({var}\s*\+).*")


def ts_get_type(line: str, var: str) -> str | None:
    pattern = ts_get_type_pattern(var)
    results = pattern.match(line)
    if results:
        return results.group(0)


def ts_build_format_id(
    matches: list[tuple[int, dict[str, Node]]], base_line: int, code_var: str
) -> str | None:
    _struct_offsets = []
    _offset = 0
    _hash_len_off = -1
    pattern = ts_get_type_pattern(code_var)
    for _, data in matches:
        if len(data) == 0:
            continue

        node = data["handler"]
        if node.start_point[0] < base_line or node.start_point[0] > base_line + 75:
            continue

        line = node.text.decode()
        if f"{code_var} +" not in line or "^" in line or "-" in line:
            continue

        ty = pattern.match(line)
        if not ty:
            continue

        match ty.group(1):
            case "uint" | "int" | "undefined4":
                _struct_offsets.append(_offset)
                _offset += 4
            case "ushort" | "short" | "undefined2":
                _struct_offsets.append(_offset)
                _hash_len_off = _offset
                _offset += 2
            case _:
                if _hash_len_off == -1:
                    _struct_offsets.append(_offset)
                    _offset += 8

    if _hash_len_off != -1:
        _info_begin = _hash_len_off - 0x10
        sv = len(list(filter(lambda x: x < _info_begin, _struct_offsets)))
        ev = len(list(filter(lambda x: x >= _info_begin + 26, _struct_offsets)))
        return f"{sv}{ev}x"


def ts_condition_literal(if_statement: Node) -> str:
    binary_expr = ts_condition_binary_expr(if_statement)
    left = binary_expr.child_by_field_name("left")
    if left.grammar_name == "number_literal":
        return left.text.decode()

    return binary_expr.child_by_field_name("right").text.decode()


def ts_condition_binary_expr(if_statement: Node) -> Node:
    condition = if_statement.child_by_field_name("condition")
    return condition.named_children[0]


def ts_condition_binary_op(if_statement: Node) -> str:
    return ts_condition_binary_expr(if_statement).children[1].text.decode()


def ts_condition_literal_pos(if_statement: Node) -> int:
    binary_expr = ts_condition_binary_expr(if_statement)
    left = binary_expr.child_by_field_name("left")
    return LEFT if left.grammar_name == "number_literal" else RIGHT


def ts_consequence_state(consequence: Node | None) -> str | None:
    if consequence is not None:
        result = tsq_state_assignment.matches(consequence)
        if len(result) > 0:
            _, data = result[0]
            return data["assign"].child_by_field_name("right").text.decode()


def ts_collect_opcode_states(
    match_data: list[tuple[int, dict[str, Node]]], end_line: int
) -> tuple[dict[str, int], set[str]]:
    state_vars = set()
    _invalid_states = set()
    _opcode_states = {}
    for _, data in match_data:
        node = data["assign"]
        if node.end_point[0] >= end_line:
            break

        if_statement = node.parent.next_named_sibling
        if if_statement is None:
            continue

        if if_statement.child_by_field_name("condition") is None:
            continue

        state_1 = node.child_by_field_name("right").text.decode()
        if state_1 in state_vars:
            _invalid_states.add(state_1)

        opcode = ts_condition_literal(if_statement)
        try:
            opcode = int(opcode)
        except ValueError:
            opcode = int(opcode, 16)
        opcode_pos = ts_condition_literal_pos(if_statement)
        operation = ts_condition_binary_op(if_statement)
        state_2 = ts_consequence_state(if_statement.child_by_field_name("consequence"))
        if state_2 is None:
            continue

        if state_2 in state_vars:
            _invalid_states.add(state_2)

        state_vars.add(state_1)
        state_vars.add(state_2)
        match operation:
            case "!=":
                # that's what we're looking for
                _opcode_states[state_1] = opcode
            case "==":
                _opcode_states[state_2] = opcode
            case "<":
                if opcode_pos == RIGHT:
                    # parameter must be smaller than opcode
                    _opcode_states[state_1] = opcode
                    _opcode_states[state_2] = opcode - 1
                else:
                    # parameter must be greater than given opcode
                    _opcode_states[state_1] = opcode
                    _opcode_states[state_2] = opcode + 1

    return _opcode_states, _invalid_states


def ts_function_body(root: Node) -> Node:
    return next(
        filter(
            lambda x: x.grammar_name == "function_definition",
            root.children,
        )
    )


def ts_state_assignment_end(body: Node) -> int:
    end_line = -1
    for _, data in tsq_func_assignment.matches(body):
        node = data["fn_assign"]
        end_line = node.end_point[0]
        break
    return end_line


def ts_state_machine_begin(body: Node, end_line: int) -> int:
    line = -1
    for _, data in C.query("(if_statement) @if").matches(body):
        node = data["if"]
        line = node.start_point[0]
        if line > end_line:
            break
    return line


def ts_vm_var(body: Node, state_machine_begin: int) -> str:
    name = "param_1"
    for _, data in tsq_vm_assignment.matches(body):
        if len(data) > 0:
            node = data["node"]
            if node.start_point[0] > state_machine_begin:
                break

            target = data.get("target")
            if target is not None:
                name = target.text.decode()
                break
    return name


def ts_assign_expr_left(expr: Node) -> str:
    if expr.grammar_name == "expression_statment":
        expr = expr.named_children[0]
    return expr.named_children[0].text.decode()


def ts_get_code_var(handler_entry: Node, context_var_name: str) -> Node | None:
    next_node = handler_entry.parent.next_named_sibling
    if f"{context_var_name} + 8" in next_node.text.decode():
        return next_node

    ty = ts_get_type(next_node.text.decode(), context_var_name)
    if ty == "long":
        return next_node

    next_node = next_node.next_named_sibling
    if f"{context_var_name} + 8" in next_node.text.decode():
        return next_node

    # we must assume this is the code variable
    if next_node.grammar_name == "expression_statement":
        ty = ts_get_type(next_node.text.decode(), context_var_name)
        if ty in ("long", "ulong"):
            return next_node


def ts_collect_handlers(tree: Tree, vm_var: str) -> dict[str, tuple[str, int]]:
    handlers = {}
    for _, data in tsq_handler_query.matches(tree.root_node):
        if len(data):
            handler_node = data["handler"]
            if f"{vm_var} + 8)" not in handler_node.text.decode():
                continue

            context_var_name = ts_assign_expr_left(handler_node)
            code_var_node = ts_get_code_var(data["handler"], context_var_name)
            if code_var_node is None:
                continue
            code_var = code_var_node.named_children[0].named_children[0].text.decode()
            code_var_line = code_var_node.start_point[0]

            format_id = ts_build_format_id(
                tsq_assignment_query.matches(data["handler"].parent.parent),
                code_var_line,
                code_var,
            )
            prev_node = handler_node.parent.prev_named_sibling
            if prev_node is None:
                # conitnue processing
                if_statement = handler_node.parent.parent.parent
                if if_statement.grammar_name != "if_statement":
                    raise NotImplementedError(str(prev_node))
                else:
                    state_var = ts_condition_literal(if_statement)
            else:
                if prev_node.grammar_name == "if_statement":
                    # get state id from here
                    state_var = ts_condition_literal(prev_node)
                else:
                    raise NotImplementedError(str(prev_node))

            handlers[state_var] = (format_id, handler_node.start_point[0] + 1)
    return handlers


def ts_walk_states(tree: Tree, opcode_def: OpcodeDef):
    body = ts_function_body(tree.root_node)
    end_line = ts_state_assignment_end(body)
    if end_line == -1:
        raise ValueError("Expected an end line!")

    state_machine_begin = ts_state_machine_begin(body, end_line)
    vm_var = ts_vm_var(body, state_machine_begin)

    opcode_states, _invalid_states = ts_collect_opcode_states(
        tsq_state_assignment.matches(body), end_line
    )
    print(
        f"[b]Discovered[/] {len(opcode_states)} possible opcode handlers with {len(_invalid_states)} bogus state(s)!"
    )
    handlers = ts_collect_handlers(tree, vm_var)
    print(f"[b]Collected[/] {len(handlers)} additional opcode handlers!")
    for state_var, (format_id, line) in handlers.items():
        if state_var not in opcode_states:
            print(f"[orange]Warning[/] Unresolved handler: {state_var} ('{format_id}')")
        else:
            opcode = opcode_states[state_var]
            prev_handler = opcode_def.opcodes.get(opcode)
            if prev_handler is None:
                opcode_def[opcode] = OpcodeHandler(
                    opcode, format_id, code_line=line, code_file="vm_dispatch_1"
                )
            else:
                prev_handler.format_id = format_id
                prev_handler.code_line = line
                prev_handler.code_file = "vm_dispatch_1"


# -----------------------------------------------------------------------------
# Args
# -----------------------------------------------------------------------------
parser = argparse.ArgumentParser()
parser.add_argument("-project", default=None)
parser.add_argument("-path", required=True)
parser.add_argument("-program", default=None)
parser.add_argument("--program-path", default="/")
parser.add_argument("-analyze", action="store_true")
parser.add_argument("-out", type=argparse.FileType("w", encoding="utf-8"), default=None)
parser.add_argument("-cout", "--csource-out-dir", dest="c_out_dir", type=pathlib.Path)
parser.add_argument("--ghidra-install-dir", default="/opt/ghidra")
argv = parser.parse_args()


# -----------------------------------------------------------------------------
# Ghidra setup
# -----------------------------------------------------------------------------
os.environ.setdefault("GHIDRA_INSTALL_DIR", argv.ghidra_install_dir)
import pyhidra

print("[b]Starting[/] Ghidra (Headless)...")
pyhidra.start()
print("[b]Finished[/] starting Ghidra")
import ghidra
from ghidra.app.util.headless import HeadlessAnalyzer
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.base.project import GhidraProject
from java.lang import String

from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def Address_ToInt(address) -> int:
    return int(str(address), 16)


def Struct_NewDef(struct_offsets: list[int], _info_begin: int) -> tuple:
    # add missing values
    end_offset = struct_offsets[-1]
    if end_offset > _info_begin + 26:
        offsets = struct_offsets[:-1]
        for x in range(_info_begin + 26 + 4, end_offset, 4):
            if x not in offsets:
                offsets.append(x)
        offsets.append(end_offset)

    # insert field definitions
    sv = len(list(filter(lambda x: x < _info_begin, struct_offsets)))
    ev = len(list(filter(lambda x: x >= _info_begin + 26, struct_offsets)))
    return sv, ev


def Struct_DefFromC(case_source: str) -> tuple:
    struct_offsets = []
    _info_begin = -1
    _prev_offset = 0
    for line in case_source.splitlines():
        line = line.strip()
        match_result = re.match(
            r"(\*\([u]?int\s*\*\)\((\([u]?long\))?\w*\s\+\s0x14\))\s=\s(\w*\s\+\s\w*);$",
            line,
        )
        if not match_result:
            continue

        offset = int(
            match_result.groups()[2].split("+")[1].strip().replace("U", ""),
            16,
        )  #
        struct_offsets.append(offset)
        if _info_begin == -1 and offset - _prev_offset == 0x08:
            _info_begin = offset - 0x0C
        _prev_offset = offset

    if _info_begin == -1:
        raise ValueError("Could not find info_begin!" + str(struct_offsets))

    return Struct_NewDef(struct_offsets, _info_begin)


def Struct_DefFromPcode(pcode_ops: list) -> tuple:
    struct_offsets = []
    _prev_offset = 0
    _info_begin = -1
    _vip_uniq = -1
    for op in pcode_ops:
        mnemonic = op.getMnemonic()
        match mnemonic:
            case "BRANCH":
                break

            case "LOAD":
                # load will be present before INT_ADD
                if _vip_uniq == -1:
                    output = op.getOutput()
                    if output.isUnique():
                        _vip_uniq = output.getAddress().getOffset()

            case "INT_ADD":
                inputs = op.getInputs()
                output = op.getOutput()
                if inputs[1].isConstant():
                    if output.isRegister() or (
                        output.isUnique() and output.getAddress().getOffset() == 0x3100
                    ):
                        offset = inputs[1].getAddress().getOffset()
                        if offset - _prev_offset == 0x08 and _info_begin == -1:
                            _info_begin = _prev_offset
                        struct_offsets.append(offset)
                        _prev_offset = offset

    if _info_begin == -1:
        raise ValueError("Could not find info_begin!" + str(struct_offsets))

    return Struct_NewDef(struct_offsets, _info_begin)


def main(flatapi: FlatProgramAPI, program) -> None:
    symbol_table = program.getSymbolTable()
    decomp = DecompInterface()
    options = DecompileOptions()
    decomp.setOptions(options)
    # decomp.toggleCCode(False)
    decomp.openProgram(program)

    potential_namespaces: dict[str, list[int]] = {}
    potential_switch_ids: dict[str, int] = {}
    print("[b]Starting[/] switch namespace lookup...")
    for symbol in symbol_table.getAllSymbols(False):
        fullname: str = symbol.getName(True)
        name: str = symbol.getName(False)
        if fullname.startswith("switchD_") and "0011" not in fullname:
            namespace_name, *_ = fullname.split("::")
            if name == "switchD":
                potential_switch_ids[namespace_name] = symbol.getID()

            if not name.startswith("caseD_"):
                continue

            if namespace_name not in potential_namespaces:
                potential_namespaces[namespace_name] = []

            potential_namespaces[namespace_name].append(symbol.getID())

    opcodes: dict[int, list[object]] = {}
    _case_addresses = set()
    _default_cases = []
    _switch_ids = []
    for namespace_name, cases in potential_namespaces.items():
        if len(cases) < 0x90:
            continue

        _switch_ids.append(
            symbol_table.getSymbol(potential_switch_ids[namespace_name]).getAddress()
        )

        for opcode in cases:
            symbol = symbol_table.getSymbol(opcode)
            opcode = int(str(symbol.getName(False)).replace("caseD_", ""), 16)
            addr = symbol.getAddress()
            addr__int = Address_ToInt(addr)
            if addr__int in _case_addresses and addr__int not in _default_cases:
                _default_cases.append(addr__int)

            prev_addr = opcodes.get(opcode)
            if prev_addr is None:
                opcodes[opcode] = [addr]
            else:
                opcodes[opcode].append(addr)

            _case_addresses.add(addr__int)

    print(
        "[b]Finished[/] namespace analysis:\n",
        f" Found {len(opcodes):#04x} switch cases with {len(_default_cases)} default cases!",
    )

    if len(_switch_ids) < 2:
        print("[red]Could not locate switch addresses![/]")
        sys.exit(1)

    first_switch_addr = _switch_ids[0]
    vm_dispatch_0 = flatapi.getFunctionContaining(first_switch_addr)
    if not vm_dispatch_0:
        print(f"Could not locate any function at address {first_switch_addr}!")
        sys.exit(1)

    print(f"[b]  >[/] vm_dispatch_0 is at 0x{vm_dispatch_0.getEntryPoint()}")

    monitor = ConsoleTaskMonitor()
    vm_dispatch_1 = None
    vm_dispatch_2 = None
    vm_dispatch_0__called_functions = list(vm_dispatch_0.getCalledFunctions(monitor))
    if len(vm_dispatch_0__called_functions) < 2:
        print("[red]Could not find any called function in vm_dispatch_0![/]")
        sys.exit(1)

    # the most important function is vm_dispatch_!
    vm_dispatch_1 = None
    vm_decode_array = None
    for func in vm_dispatch_0__called_functions:
        if func.getName().startswith("<EXTERNAL>"):
            continue

        if func.getParameterCount() > 20 and vm_dispatch_1 is None:
            vm_dispatch_1 = func

        sf = func.getStackFrame()
        stack_variables = sf.getStackVariables()
        if len(stack_variables) == 2:
            # There are only two stack variables at -0x38 and -0x40
            if stack_variables[0].getStackOffset() == -0x40:
                if stack_variables[1].getStackOffset() == -0x38:
                    vm_decode_array = func

    if not vm_dispatch_1:
        print("[red]Could not locate vm_dispatch_1![/]")
        sys.exit(1)

    print(f"[b]  >[/] vm_dispatch_1 is at 0x{vm_dispatch_1.getEntryPoint()}")

    vm_dispatch_2 = flatapi.getFunctionContaining(_switch_ids[1])
    print(f"[b]  >[/] vm_dispatch_2 is at 0x{vm_dispatch_2.getEntryPoint()}")

    if vm_decode_array:
        print(f"[b]  >[/] vm_decode_array is at 0x{vm_decode_array.getEntryPoint()}")

    opcode_def = OpcodeDef(
        Address_ToInt(vm_dispatch_0.getEntryPoint()) - 0x00100000,
        Address_ToInt(vm_dispatch_1.getEntryPoint()) - 0x00100000,
        Address_ToInt(vm_dispatch_2.getEntryPoint()) - 0x00100000,
        Address_ToInt(vm_decode_array.getEntryPoint()) - 0x00100000
        if vm_decode_array
        else -1,
        default_cases=list(map(lambda x: x - 0x00100000, _default_cases)),
    )
    covered_opcodes = set()
    # collect opcodes via source code analysis
    for i, func in enumerate([vm_dispatch_0, vm_dispatch_2]):
        print(f"[b]Decompiling[/] pairipvm::VMDispatch{0 if i == 0 else 2}...")
        source_name = f"vm_dispatch_{0 if i == 0 else 2}"
        with console.status(f"Running Ghidra::DecompileFunction({source_name})"):
            result = decomp.decompileFunction(func, 60, monitor)
        decomp_func = result.getDecompiledFunction()
        c_source = decomp_func.getC()

        print("[b]Finished[/] decompiling")
        for c_case_text in c_source.split("case"):
            try:
                i = c_case_text.index(":")
                try:
                    opcode = int(c_case_text[:i])
                except ValueError:
                    opcode = int(c_case_text[:i], 16)
            except ValueError as e:
                continue

            # if opcode not in missing_opcodes:
            #     continue
            i = c_case_text.index("\n")
            try:
                sv, ev = Struct_DefFromC(c_case_text[i + 1 :])
                addresses = opcodes[opcode]
                print(
                    f"[b]Opcode[/] {opcode:#04x} at {addresses} default={list(map(hex, _default_cases))} formatid='{sv}{ev}x'"
                )
                calls_vm_decode_array = False
                if vm_decode_array:
                    calls_vm_decode_array = vm_decode_array.getName() in c_case_text

                opcode_def[opcode] = OpcodeHandler(
                    opcode,
                    f"{sv}{ev}x",
                    addresses=list(
                        map(lambda x: Address_ToInt(x) - 0x00100000, addresses)
                    ),
                    code_file=source_name,
                    decodes_array=calls_vm_decode_array,
                )
                covered_opcodes.add(opcode)
                # save output
                if argv.c_out_dir and argv.c_out_dir.exists():
                    with open(
                        str(argv.c_out_dir / f"opcode_{opcode:#04x}.c"), "w"
                    ) as fp:
                        fp.write(f"void GVM__VMOp_Handler__x{opcode:02x}(void) {{\n")
                        fp.write(c_case_text[i + 1 :])
                        fp.write("}")
            except ValueError:
                pass

    # decomp.toggleCCode(False)
    print("[b]Analyzing[/] case addresses...")
    for opcode, addresses in opcodes.items():
        if opcode in covered_opcodes:
            continue

        for addr in addresses:
            addr__int = Address_ToInt(addr)
            if addr__int in _default_cases:
                continue

            func = flatapi.createFunction(
                addr, f"pairipvm::OpcodeHandler::x{opcode:02x}"
            )
            result = decomp.decompileFunction(func, 60, monitor)
            high_func = result.getHighFunction()
            try:
                sv, ev = Struct_DefFromPcode(high_func.getPcodeOps())
                print(
                    f"[b]Opcode[/] {opcode:#04x} at {addresses} default={list(map(hex, _default_cases))} formatid='{sv}{ev}x'"
                )
                opcode_def[opcode] = OpcodeHandler(
                    opcode,
                    f"{sv}{ev}x",
                    addresses=list(
                        map(lambda x: Address_ToInt(x) - 0x00100000, addresses)
                    ),
                )
                covered_opcodes.add(opcode)
            except ValueError:
                continue

    print(
        f"[b]Resolved[/] {len(covered_opcodes)} out of {len(opcodes)} opcodes so far!"
    )
    missing = list(filter(lambda x: x not in covered_opcodes, opcodes))
    print(f"[b]Missing[/] {len(missing)} out of {len(opcodes)} opcodes")

    print("[b]Decompiling[/] pairipvm::Dispatch1...")
    # decomp.toggleCCode(True)
    with console.status("Running Ghidra::DecompileFunction(vm_dispatch_1)"):
        decomp_result = decomp.decompileFunction(vm_dispatch_1, 120, monitor)
        error = decomp_result.getErrorMessage()
        if error:
            print("[red]Error:[/] " + str(error))
            sys.exit(1)
    print("[b]Finished[/] decompilation")
    if argv.c_out_dir:
        with open(str(argv.c_out_dir / "vm_dispatch_1.c"), "w") as fp:
            fp.write(decomp_result.getDecompiledFunction().getC())

    print("[b]Analyzing[/] ast source of pairipvm::Dispatch1...")
    parser = Parser()
    parser.set_language(C)

    tree = parser.parse(decomp_result.getDecompiledFunction().getC().encode())
    ts_walk_states(tree, opcode_def)
    missing = len(
        list(
            filter(
                lambda x: x[1].format_id is None is None,
                opcode_def.opcodes.items(),
            )
        )
    )
    print("[b]Finished[/] analysis:")
    print(f"[b]  >[/] Total   opcodes: {len(opcode_def.opcodes):#x}")
    print(f"[b]  >[/] Missing opcodes: {missing}")

    if argv.out:
        json.dump(dataclasses.asdict(opcode_def), argv.out, indent=2)


if argv.project is None:
    if argv.analyze:
        print(f"[b]Starting[/] analysis on program at {argv.path!r}...")
    else:
        print(f"[b]Importing[/] program at {argv.path!r}...")
    # First switch statement is always at "0x0014XXXX"
    with pyhidra.open_program(
        os.path.abspath(argv.path), analyze=argv.analyze
    ) as flatapi:
        print("[b]Finished[/] analysis")
        main(flatapi, flatapi.getCurrentProgram())

else:
    print(f"[b]Importing[/] project at {argv.path!r}...")

    # First switch statement is always at "0x0014XXXX"
    project = GhidraProject.openProject(os.path.abspath(argv.path), argv.project, True)
    program = project.openProgram(argv.program_path, argv.program, argv.analyze)
    flatapi = FlatProgramAPI(program)
    main(flatapi, program)
