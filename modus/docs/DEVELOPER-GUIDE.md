# Modus Developer Guide

This guide provides information for new developers working on the Modus project, covering setup, development workflows, and important concepts.

## Getting Started

### Prerequisites

Before you begin, you'll need:

1. **Common Lisp Implementation**:
   - SBCL (Steel Bank Common Lisp) is the recommended implementation
   - Version 2.2.0 or later is recommended

2. **Development Tools**:
   - Git for version control
   - QEMU for running and testing built images
   - A text editor with Lisp support (Emacs/SLIME recommended)

3. **Basic Knowledge**:
   - Common Lisp programming
   - Operating system fundamentals
   - x86 architecture (helpful but not required)

### Setting Up the Development Environment

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-org/modus.git
   cd modus
   git submodule update --init --recursive
   ```

2. **Install Dependencies**:
   ```bash
   # On Debian/Ubuntu
   sudo apt-get install sbcl qemu-system-x86

   # On macOS using Homebrew
   brew install sbcl qemu
   ```

3. **Configure SBCL**:
   It's recommended to create an `.sbclrc` file in your home directory with:
   ```lisp
   (require :asdf)
   (push "/path/to/modus/" asdf:*central-registry*)
   ```

4. **Test Your Setup**:
   ```bash
   ./build-modus.sh
   ./run-modus.sh
   ```

## Project Architecture

Modus is organized into several key components:

### Core Components

1. **Memory Management** (`src/core/memory.lisp`):
   - Region-based memory allocation
   - Memory protection and security
   - Foundation for capability-based access control

2. **Hardware Abstraction** (`src/core/hardware.lisp`):
   - Device management and discovery
   - Driver registration system
   - Resource allocation for hardware

### Security Framework

The security framework is capability-based and will include:

- Capability tokens for resource access control
- Security domains for process isolation
- Resource protection and validation

### Runtime Environment

The runtime will include:

- Enhanced REPL for development
- Dynamic code loading and patching
- Debugging and introspection tools

### System Integration

Modus builds upon Movitz for:

- Bootloading and system initialization
- Basic hardware access
- Low-level memory operations

## Development Workflow

### Host-Side Development

Most development happens on the host system using SBCL:

1. **Load the System**:
   ```lisp
   (require :asdf)
   (asdf:load-system :modus)
   ```

2. **Make Changes**:
   - Edit source files in your text editor
   - Use the REPL to test changes interactively
   - Run unit tests for verification

3. **Build and Test**:
   ```bash
   ./build-modus.sh
   ./run-modus.sh
   ```

### Target-Side Development

Some features must be tested on the actual Modus environment:

1. **Make Changes on Host**
2. **Build a Test Image**
3. **Run in QEMU**
4. **Use the Modus REPL for Debugging**

### Development Guidelines

1. **Reader Conditionals**:
   Use reader conditionals to handle differences between host and target:
   ```lisp
   #+(and sbcl (not movitz))
   (host-only-code)
   
   #+(and movitz)
   (target-only-code)
   ```

2. **Testing Strategy**:
   - Test in the host environment first
   - Create unit tests for components
   - Test on the target only when necessary

3. **Documentation**:
   - Add docstrings for all functions
   - Update relevant documents when making changes
   - Document design decisions in comments

## Common Development Tasks

### Adding a New Component

1. Create appropriate package definitions
2. Add file to the ASDF system definition
3. Implement the component with proper documentation
4. Add tests for the new functionality
5. Integrate with existing components

### Debugging Tips

1. **Host-Side Debugging**:
   - Use SBCL's debugging tools
   - Set breakpoints with `(break)`
   - Inspect variables with `(inspect)`

2. **Target-Side Debugging**:
   - Use Movitz's debugging capabilities
   - Check console output in QEMU
   - Use memory dumps for low-level issues

3. **Common Issues**:
   - Memory leaks: Check allocations and deallocations
   - Boot failures: Verify bootloader integration
   - Hardware issues: Check device initialization

### Build System

The build system uses ASDF for component management:

1. **Adding Files**:
   Update `modus.asd` to include new files with proper dependencies.

2. **Building Images**:
   The `build-modus.sh` script handles image creation:
   ```bash
   ./build-modus.sh [output-path]
   ```

3. **Running in QEMU**:
   The `run-modus.sh` script manages QEMU execution:
   ```bash
   ./run-modus.sh [image-path]
   ```

## Memory Management

The memory management system is a key component of Modus:

### Memory Regions

Memory is managed through the `memory-region` struct:
```lisp
(defstruct memory-region
  (start 0 :type (unsigned-byte 64))
  (size 0 :type (unsigned-byte 64))
  (flags 0 :type (unsigned-byte 32))
  (protection 0 :type (unsigned-byte 32))
  (next nil :type (or null memory-region)))
```

### Working with Memory

```lisp
;; Allocate a memory region
(defvar *my-region* 
  (allocate-memory 4096 :protection (logior +protection-read+ +protection-write+)))

;; Use with-memory-region for automatic cleanup
(with-memory-region (buf 1024 :protection +protection-read+)
  ;; Use buf here
  )

;; Explicitly deallocate
(deallocate-memory *my-region*)
```

## Hardware Abstraction

The hardware abstraction layer provides device management:

### Device Management

```lisp
;; Create a device representation
(defvar *keyboard* 
  (make-device :type :keyboard :vendor-id #x1234 :device-id #x5678))

;; Register a driver
(define-driver keyboard-driver :keyboard
  ;; Driver initialization code
  (format t "Keyboard initialized~%"))

;; Access hardware safely
(with-hardware-access (*keyboard* :exclusive t)
  ;; Perform hardware operations
  )
```

## Future Directions

Current development priorities include:

1. Memory protection implementation
2. Initial capability framework
3. Enhanced driver support
4. Better development tools

## Troubleshooting

### Common Errors

1. **ASDF Component Errors**:
   - Check package definitions
   - Verify file paths in ASDF definition
   - Ensure proper dependency order

2. **Build Failures**:
   - Check Movitz integration
   - Verify proper paths in build script
   - Look for compilation errors in output

3. **Runtime Issues**:
   - Check memory allocations
   - Verify hardware initialization
   - Look for capability validation errors

### Getting Help

- Check the `.goosenotes` file for developer notes
- Review documentation in the `doc/` directory
- Consult the project wiki (when available)

## Coding Standards

1. **Naming Conventions**:
   - Package names: lowercase with dots (e.g., `modus.core`)
   - Function names: kebab-case (e.g., `allocate-memory`)
   - Constants: earmuffs with plus signs (e.g., `+page-size+`)
   - Variables: earmuffs (e.g., `*memory-regions*`)

2. **Documentation**:
   - Docstrings for all functions and structures
   - Header comments for files explaining purpose
   - Comments for complex algorithms

3. **Style Guidelines**:
   - Prefer simplicity and clarity
   - Follow common Lisp style conventions
   - Use meaningful names rather than abbreviations

## Resources

- [Common Lisp HyperSpec](http://www.lispworks.com/documentation/HyperSpec/Front/index.htm)
- [Practical Common Lisp](http://www.gigamonkeys.com/book/)
- [Movitz Documentation](https://github.com/dym/movitz)
- [SBCL Manual](http://www.sbcl.org/manual/)

## Contributing

When contributing to Modus:

1. Fork the repository
2. Create a feature branch
3. Make your changes with proper documentation
4. Run tests to verify functionality
5. Submit a pull request with a clear description

See [CONTRIBUTING.md](/CONTRIBUTING.md) for more detailed guidelines.

## Conclusion

Modus is an ambitious project to create a modern Lisp Machine environment. By following this guide, you should be able to set up your development environment and start contributing to the project. Remember that Modus is still in early development, so many components are evolving rapidly.

Welcome to the Modus development community!