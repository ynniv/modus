# Modus and Movitz: Integration Strategy

This document explains the relationship between Modus and Movitz, detailing how Modus builds upon Movitz's foundation while extending it with new capabilities.

## What is Movitz?

[Movitz](https://github.com/dym/movitz) is a Common Lisp development framework for x86 hardware created by Frode Vatvedt Fjeld. It provides a minimal Lisp system that runs directly on bare metal without requiring an underlying operating system. Key features include:

- A bootloader for x86 systems
- Core Common Lisp functionality
- Basic memory management and garbage collection
- Hardware drivers for essential devices
- Simple REPL and debugging support

Movitz serves as an excellent foundation for bare-metal Lisp development, providing the low-level infrastructure needed to boot and run Lisp code directly on hardware.

## How Modus Builds on Movitz

Modus uses Movitz as its underlying foundation while significantly expanding its capabilities:

### Foundation and Extension

1. **Core System Services**
   - Movitz provides basic memory access and hardware interaction
   - Modus adds higher-level abstractions, security, and advanced management
   
2. **Development Environment**
   - Movitz offers a simple REPL and debugging interface
   - Modus aims to create a fully interactive development environment

3. **Hardware Support**
   - Movitz supports basic PC hardware
   - Modus extends this with modern device support and drivers

4. **Security Model**
   - Movitz has minimal security concepts
   - Modus adds a comprehensive capability-based security framework

### Integration Approach

Modus integrates with Movitz using a layered approach:

1. **Direct Usage**
   - Some Movitz components are used directly without modification
   - Examples: bootloader, memory access primitives, basic hardware drivers

2. **Wrapped Extension**
   - Other components are wrapped with Modus interfaces that add functionality
   - Examples: memory management, device drivers, runtime environment

3. **Complete Replacement**
   - Some areas will eventually be reimplemented with Modus-specific solutions
   - Examples: advanced garbage collection, security framework, UI system

## Integration Examples

### Memory Management

**Movitz Provides:**
- Low-level memory access through the `memref` system
- Basic stop-and-copy garbage collection
- Simple memory allocation

**Modus Adds:**
- Memory region abstraction with protection attributes
- Capability-based memory access controls
- Enhanced garbage collection with generational features
- Memory protection using x86 page tables

### Hardware Abstraction

**Movitz Provides:**
- Basic device drivers (keyboard, display, disk)
- Interrupt handling
- I/O port access

**Modus Adds:**
- Unified device abstraction framework
- Driver registration and discovery
- Modern device support (USB, networking, graphics)
- Secure access control for hardware resources

### Runtime Environment

**Movitz Provides:**
- Basic Common Lisp functionality
- Simple REPL
- Exception handling

**Modus Adds:**
- Enhanced REPL with history and completion
- Advanced debugging tools
- Package management system
- Dynamic code loading and patching

## Development Workflow

The integration between Movitz and Modus affects the development workflow:

1. **Submodule Management**
   - Movitz is included as a git submodule
   - Changes to Movitz can be tracked and managed independently

2. **Build Process**
   - Modus build scripts integrate with Movitz's image creation
   - ASDF system definitions bridge the components

3. **Testing Strategy**
   - Components are tested in isolation when possible
   - Integration tests verify the interaction between Modus and Movitz

4. **Documentation**
   - Clear distinction between Movitz and Modus functionality
   - Integration points are well-documented
   - Compatibility considerations are noted

## Future Evolution

The relationship between Modus and Movitz will evolve over time:

1. **Short Term**
   - Direct use of many Movitz components
   - Focus on integration and extension

2. **Medium Term**
   - Gradual replacement of some Movitz subsystems
   - Enhanced interfaces between components

3. **Long Term**
   - Potential for complete reimplementation of some areas
   - Possible contributions back to Movitz for mutual benefit

## Practical Considerations

### When to Use Movitz Directly

- For low-level hardware access where performance is critical
- For stable, well-tested functionality that doesn't need enhancement
- For core bootloading and initialization

### When to Extend or Wrap

- When adding security controls to existing functionality
- When adding higher-level abstractions
- When integrating with other Modus subsystems

### When to Replace

- When fundamental architectural differences require new implementation
- When security requirements necessitate different approaches
- When adding capabilities that would require extensive modification of Movitz code

## Conclusion

Modus builds upon Movitz's solid foundation while extending it with modern concepts of security, interactive development, and hardware support. This strategy allows us to leverage mature, proven code while progressively building toward our vision of a modern Lisp Machine environment.

By clearly documenting the relationship between these two systems, we aim to maintain a clean architecture while facilitating collaboration and ensuring proper attribution of the foundational work provided by Movitz.