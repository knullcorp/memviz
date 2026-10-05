# memviz

Visualizador **paso a paso** de shellcode / assembly x86-64. Ejecuta tu código
una instrucción a la vez (emulado con [Unicorn](https://www.unicorn-engine.org/))
y muestra cómo cambian los **registros** y la **pila** en cada paso, resaltando
lo que se modificó. Sirve para *ver* cómo se va escribiendo en memoria mientras
aprendes assembly.

Funciona en cualquier Linux (y macOS/Windows): Unicorn **emula** el x86-64, así
que no depende de la CPU del host.

## Instalación

```bash
pip install unicorn capstone pyelftools
# ademas, para --asm y --watch necesitas el ensamblador NASM:
#   sudo pacman -S nasm        # Arch
#   sudo apt install nasm      # Debian/Ubuntu
```

En Arch Linux:

```bash
sudo pacman -S python-unicorn python-capstone python-pyelftools nasm
```

## Uso

```bash
# extrae el codigo de un binario (.text o .shellcode) y lo recorre
python3 memviz.py <binario> [seccion]

# codigo en hex directo
python3 memviz.py --hex 4831db66bb7921...

# ensambla un snippet (sintaxis Intel) y lo recorre
python3 memviz.py --asm mi_codigo.asm

# modo VIVO: re-ejecuta cada vez que guardas el archivo (como el live-preview de HTML)
python3 memviz.py --watch mi_codigo.asm
```

Agrega `--auto` a los dos primeros modos para correr sin pausas. En modo
interactivo: `Enter` = siguiente instrucción, `q` + `Enter` = salir.

Colores: **verde** = registro que cambió · **amarillo** = qword de la pila que
cambió · cian = RSP y syscalls.

## Qué emula

- CPU x86-64 completa (todas las instrucciones, vía Unicorn).
- Syscalls `write` (imprime a la salida), `exit`/`exit_group` (termina) y
  `execve` (muestra el path que lanzaría). Los demás se muestran y se saltan.

## Límite

Solo carga el código (`.text` / `.shellcode`) y una pila; **no** mapea `.data`
ni libc. Es ideal para shellcode autocontenido. Para programas que llaman a
`scanf`/`printf` o leen de `.data`, usa `gdb`/pwndbg, que corren el binario real
completo.
