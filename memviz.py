#!/usr/bin/python3
"""
memviz.py - visualizador paso a paso de shellcode / assembly.

Ejecuta tu codigo UNA instruccion a la vez (emulado con Unicorn) y muestra
como cambian los registros y la PILA en cada paso, resaltando lo que se
modifico. Sirve para "ver" como se va escribiendo en memoria.

Uso:
    python3 memviz.py <binario> [seccion]     # extrae .text / .shellcode
    python3 memviz.py --hex <hexstring>       # codigo en hex directo
    python3 memviz.py --asm <archivo.asm>     # ensambla un snippet y lo corre
    python3 memviz.py --watch <archivo.asm>   # modo VIVO: re-corre al guardar
    (agrega --auto para correr sin pausas en los dos primeros)

Controles (modo interactivo): Enter = siguiente instruccion, q + Enter = salir.
--asm y --watch necesitan pwntools (para ensamblar); los demas no.
"""
import re
import sys

from unicorn import *
from unicorn.x86_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# --- colores ---
R = "\033[0m"; B = "\033[1m"
GREEN = "\033[32m"; YELLOW = "\033[33m"; CYAN = "\033[36m"; GREY = "\033[90m"

# --- mapa de memoria del emulador ---
CODE_BASE  = 0x1000000
CODE_SIZE  = 0x10000
STACK_BASE = 0x200000
STACK_SIZE = 0x100000
RSP_START  = STACK_BASE + STACK_SIZE // 2

REGS = [
    ("rax", UC_X86_REG_RAX), ("rbx", UC_X86_REG_RBX), ("rcx", UC_X86_REG_RCX), ("rdx", UC_X86_REG_RDX),
    ("rsi", UC_X86_REG_RSI), ("rdi", UC_X86_REG_RDI), ("rbp", UC_X86_REG_RBP), ("rsp", UC_X86_REG_RSP),
    ("r8",  UC_X86_REG_R8),  ("r9",  UC_X86_REG_R9),  ("r10", UC_X86_REG_R10), ("r11", UC_X86_REG_R11),
    ("r12", UC_X86_REG_R12), ("r13", UC_X86_REG_R13), ("r14", UC_X86_REG_R14), ("r15", UC_X86_REG_R15),
]

md = Cs(CS_ARCH_X86, CS_MODE_64)


def load_code_from_binary(path, section=None):
    from elftools.elf.elffile import ELFFile
    with open(path, "rb") as f:
        elf = ELFFile(f)
        sec = (elf.get_section_by_name(section) if section
               else elf.get_section_by_name(".text") or elf.get_section_by_name(".shellcode"))
        if sec is None:
            sys.exit("no encontre .text ni .shellcode; pasa la seccion como 2o argumento")
        return sec.data()


def read_regs(mu):
    return {name: mu.reg_read(uid) for name, uid in REGS}


def show_regs(cur, prev):
    items = list(cur.items())
    for i in range(0, len(items), 4):
        row = ""
        for name, val in items[i:i + 4]:
            changed = prev is not None and prev[name] != val
            col = GREEN + B if changed else GREY
            row += f"{col}{name:>3} 0x{val:016x}{R}  "
        print("  " + row)


def show_stack(mu, prev_mem, nqwords=8):
    rsp = mu.reg_read(UC_X86_REG_RSP)
    cur_mem = {}
    print(f"  {GREY}pila (desde RSP hacia arriba):{R}")
    for i in range(nqwords):
        addr = rsp + i * 8
        data = bytes(mu.mem_read(addr, 8))
        val = int.from_bytes(data, "little")
        cur_mem[addr] = val
        changed = prev_mem is not None and prev_mem.get(addr) != val
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        ptr = f" {CYAN}<- RSP{R}" if i == 0 else ""
        col = YELLOW + B if changed else GREY
        print(f"    {col}0x{addr:06x}:  {val:016x}  |{txt}|{R}{ptr}")
    return cur_mem


def hook_syscall(mu, user):
    rax = mu.reg_read(UC_X86_REG_RAX)
    if rax == 1:  # write(fd, buf, len)
        fd  = mu.reg_read(UC_X86_REG_RDI)
        buf = mu.reg_read(UC_X86_REG_RSI)
        ln  = mu.reg_read(UC_X86_REG_RDX)
        data = bytes(mu.mem_read(buf, ln))
        user["output"] += data
        print(f"  {CYAN}>> syscall write(fd={fd}, len={ln}) imprime: {data!r}{R}")
        mu.reg_write(UC_X86_REG_RAX, ln)
    elif rax in (60, 231):  # exit / exit_group
        code = mu.reg_read(UC_X86_REG_RDI)
        print(f"  {CYAN}>> syscall exit({code}) -> fin del programa{R}")
        user["done"] = True
        mu.emu_stop()
    else:
        print(f"  {CYAN}>> syscall #{rax} (no emulado, lo salto){R}")


def run_trace(code, auto=False):
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(CODE_BASE, CODE_SIZE)
    mu.mem_map(STACK_BASE, STACK_SIZE)
    mu.mem_write(CODE_BASE, code)
    mu.reg_write(UC_X86_REG_RSP, RSP_START)

    state = {"output": b"", "done": False}
    mu.hook_add(UC_HOOK_INSN, hook_syscall, user_data=state, aux1=UC_X86_INS_SYSCALL)

    print(f"{B}== memviz =={R}  {len(code)} bytes de codigo. "
          f"{GREEN}verde{R}=registro cambiado, {YELLOW}amarillo{R}=pila cambiada.\n")

    pc = CODE_BASE
    end = CODE_BASE + len(code)
    prev_regs = None
    prev_mem = None
    step = 0

    while not state["done"] and pc < end and step < 2000:
        chunk = bytes(mu.mem_read(pc, min(16, end - pc)))
        ins = next(md.disasm(chunk, pc), None)
        if ins is None:
            print(f"{GREY}(no pude desensamblar en 0x{pc:x}, fin){R}")
            break

        step += 1
        print(f"{B}[paso {step}]{R} 0x{pc:x}:  "
              f"{B}{ins.mnemonic} {ins.op_str}{R}   "
              f"{GREY}({ins.bytes.hex()}){R}")

        try:
            mu.emu_start(pc, end, count=1)
        except UcError as e:
            target = mu.reg_read(UC_X86_REG_RIP)
            print(f"{GREY}  se detuvo: {e} (intento ejecutar en 0x{target:x}){R}")
            if "FETCH" in str(e):
                print(f"  {CYAN}pista: saltaste a una direccion sin codigo. "
                      f"un 'ret' saca el tope de la pila y salta ahi; si no hay un "
                      f"return address valido (aqui 0x0), crashea.{R}")
            break

        cur_regs = read_regs(mu)
        show_regs(cur_regs, prev_regs)
        prev_mem = show_stack(mu, prev_mem)
        prev_regs = cur_regs
        print()

        if not state["done"]:
            pc = mu.reg_read(UC_X86_REG_RIP)
            if not auto:
                try:
                    if input().strip().lower() == "q":
                        break
                except EOFError:
                    break

    if state["output"]:
        print(f"{B}salida del programa:{R} {state['output']!r}")


def preprocess_asm(src):
    """Hace tolerante el snippet: quita comentarios estilo NASM (';') y
    directivas que pwntools ya agrega (global/section/bits/_start:), para que
    puedas pegar codigo casi tal cual en vez de instrucciones peladas."""
    drop = re.compile(r"^\s*(global|extern|section|segment|bits|default|cpu)\b", re.I)
    label_start = re.compile(r"^\s*_{1,2}start\s*:\s*$", re.I)
    out = []
    for line in src.splitlines():
        line = line.split(";", 1)[0]          # comentario NASM ;
        if drop.match(line) or label_start.match(line):
            continue
        out.append(line)
    return "\n".join(out)


def assemble(src):
    import os
    os.environ.setdefault("TERM", "xterm")
    from pwn import asm, context
    context.update(arch="amd64", os="linux", log_level="error")
    return asm(preprocess_asm(src))


def watch(path):
    import os, time
    print(f"{CYAN}watch:{R} mirando {path} — guarda el archivo para re-ejecutar "
          f"(Ctrl+C para salir)")
    last = None
    while True:
        try:
            m = os.path.getmtime(path)
        except FileNotFoundError:
            m = None
        if m != last:
            last = m
            print("\033[2J\033[H", end="")  # limpiar pantalla
            print(f"{CYAN}=== {path}  (guardado) ==={R}\n")
            if m is None:
                print(f"{GREY}no existe el archivo todavia...{R}")
            else:
                try:
                    code = assemble(open(path).read())
                    run_trace(code, auto=True)
                except Exception as e:
                    print(f"{GREY}error al ensamblar/correr: {e}{R}")
        time.sleep(0.3)


def main():
    args = sys.argv[1:]
    auto = "--auto" in args
    args = [a for a in args if a != "--auto"]
    if not args:
        sys.exit(__doc__)

    if args[0] == "--watch":
        if len(args) < 2:
            sys.exit("uso: memviz.py --watch <archivo.asm>")
        try:
            watch(args[1])
        except KeyboardInterrupt:
            print("\nbye")
        return

    if args[0] == "--asm":
        if len(args) < 2:
            sys.exit("uso: memviz.py --asm <archivo.asm>")
        code = assemble(open(args[1]).read())
    elif args[0] == "--hex":
        code = bytes.fromhex(args[1].replace(" ", ""))
    else:
        code = load_code_from_binary(args[0], args[1] if len(args) > 1 else None)

    run_trace(code, auto=auto)


if __name__ == "__main__":
    main()
