# Modus Build System Notes

## Current Status (2025-03-15)

The Modus build system is currently functional with the following components:

- ASDF-based system definition in `modus.asd`
- Build script (`build-modus.sh`) for creating bootable images
- Run script (`run-modus.sh`) for testing in QEMU
- Image creation via Movitz integration

## Build Process Overview

The Modus build process consists of these key steps:

1. **Environment Setup**
   - SBCL is used as the host Common Lisp implementation
   - ASDF loads the system definitions
   - Binary-types library is loaded for low-level data manipulation

2. **Component Compilation**
   - Core Modus packages are compiled
   - Dependency tree is resolved via ASDF
   - Host-side components are fully compiled

3. **Image Creation**
   - Movitz is loaded as a dependency
   - A bootable image is created using Movitz's infrastructure
   - Modus components are integrated into the image
   - The final image is dumped to disk

4. **Runtime Execution**
   - QEMU loads the bootable image
   - Movitz bootloader initializes the system
   - Modus runtime environment is started

## Previous Issues

- **ASDF Component Parsing Error**: 
  ```
  Error while parsing arguments to DESTRUCTURING-BIND:
  too few elements in () to satisfy lambda list (TYPE NAME &REST REST ...)
  at least 2 expected, but got 0
  ```
  - Issue was related to NIL component lists in the package definition
  - Resolved by restructuring the ASDF components and ensuring proper dependencies

- **Package Definition Conflicts**:
  - Multiple packages with overlapping exports
  - Resolved by creating clearer package hierarchy and using package-local nicknames

- **Path Resolution**:
  - Difficulties with relative paths during build
  - Fixed by using absolute paths in the build script

## Current ASDF System Structure

The current ASDF system definition in `modus.asd` defines three systems:

1. **modus**: Main system with core components
   - Includes package definitions and source code modules
   - Structured with clear dependencies between components

2. **modus/image**: Image creation system
   - Depends on main modus system
   - Handles bootable image creation via Movitz

3. **modus/tests**: Test suite
   - Contains test components for verifying system functionality
   - Currently minimal but planned for expansion

## Movitz Integration

The integration with Movitz is handled through:

1. **build-image.lisp**:
   - Loads Movitz when needed
   - Calls Movitz's image creation functions
   - Configures image parameters

2. **Library Management**:
   - Movitz is included as a git submodule in `lib/movitz/`
   - ASDF's central registry is configured to find Movitz

## Build Environment Requirements

To build Modus, you need:

1. **SBCL (Steel Bank Common Lisp)**:
   - Required for host-side development
   - Must be run with batch flags (`--non-interactive --disable-debugger`) to prevent hanging

2. **ASDF (Another System Definition Facility)**:
   - Used for component management and building
   - Should be included with SBCL

3. **QEMU**:
   - Required for running the built image
   - Supports various emulation options for testing

4. **Git**:
   - Required for submodule management
   - Handles versioning of Movitz dependency

## Environment Variables

The build process respects these environment variables:

- `MODUS_BUILD_DIR`: Override the build directory (default: current directory)
- `MODUS_IMAGE_SIZE`: Set the size of the bootable image (default: 1.44MB)
- `MODUS_DEBUG`: Enable debug output when set to "1"

## Best Practices

When working with the Modus build system:

1. **Test Incrementally**:
   - Test components in SBCL before full image builds
   - Use the REPL for rapid development

2. **Package Management**:
   - Keep package definitions clear and organized
   - Avoid circular dependencies between packages

3. **Testing**:
   - Run tests before building a full image
   - Create targeted tests for specific components

4. **Image Backups**:
   - Save working images before major changes
   - Use version control for tracking changes

## Common Build Issues and Solutions

1. **Missing Dependency Errors**:
   - Ensure ASDF can find all required systems
   - Check `asdf:*central-registry*` configuration

2. **Compilation Failures**:
   - Usually caused by syntax errors or missing dependencies
   - Test components individually to isolate issues

3. **Image Creation Failures**:
   - Verify Movitz is properly loaded and configured
   - Check for incompatible changes in Movitz API

4. **QEMU Errors**:
   - Ensure QEMU is correctly installed
   - Verify image format is compatible with QEMU options

## Future Build System Enhancements

1. **Continuous Integration**:
   - Set up automatic testing and building
   - Create CI pipeline for pull requests

2. **Development Environment Improvements**:
   - Create developer-friendly REPL setup
   - Implement hot-reloading for faster development

3. **Build Optimization**:
   - Speed up the build process with parallel compilation
   - Create incremental build capabilities

4. **Image Customization**:
   - Allow more configuration options for built images
   - Support different hardware targets

## Notes on Binary Size and Performance

- Current image size: approximately 1.44MB (standard floppy)
- Boot time: varies depending on hardware (5-10 seconds in QEMU)
- Memory footprint: minimal, with room for expansion
- Build time: typically under 1 minute on modern hardware

## References

- ASDF Manual: https://common-lisp.net/project/asdf/asdf.html
- Movitz Repository: https://github.com/dym/movitz
- SBCL Manual: http://www.sbcl.org/manual/
- QEMU Documentation: https://www.qemu.org/docs/master/