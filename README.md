# Modus

A bare-metal Lisp environment built on [Movitz](https://github.com/dym/movitz). Boots directly on x86 hardware (or QEMU) into an interactive Common Lisp REPL.

## Building

Requires SBCL and QEMU.

```bash
./modus/scripts/build.sh
```

## Running

```bash
./modus/scripts/run.sh
```

Boots to a `MODUS(1):` REPL prompt over serial console.

## SSH Server

```bash
./modus/scripts/run-ssh-server.sh
```

Boots Modus, initializes networking and SSH, then accepts connections on port 2222.

## Project Structure

- `lib/binary-types/` - Binary data type library
- `lib/movitz/` - Movitz bare-metal Lisp framework
- `modus/build/` - ASDF system definition and package setup
- `modus/src/` - Modus source (crypto, networking, drivers, REPL)
- `modus/scripts/` - Build and run scripts
- `modus/docs/` - Design documents

## License

MIT
