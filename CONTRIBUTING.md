# Contributing to Modus

## Development Philosophy

Modus is built on the principle of complete system malleability while maintaining security and stability. When contributing, keep in mind:

1. Every component should be modifiable at runtime
2. Security is a primary concern, not an afterthought
3. Code should be self-documenting and well-structured
4. Performance is important but shouldn't compromise flexibility

## Getting Started

1. Fork the repository
2. Set up your development environment:
   - Install SBCL
   - Clone and build Movitz
   - Set up QEMU/KVM for testing
3. Create a feature branch
4. Make your changes
5. Submit a pull request

## Development Environment

### Required Tools
- SBCL (Steel Bank Common Lisp)
- Movitz (from source)
- QEMU/KVM
- Git

### Recommended Setup
```bash
# Clone Movitz
git clone https://github.com/dym/movitz.git
cd movitz
# Build Movitz (instructions needed)

# Clone Modus
git clone https://github.com/your-org/modus.git
cd modus
# Set up development environment
```

## Coding Standards

### Common Lisp Style
- Follow modern Common Lisp conventions
- Use meaningful symbol names
- Document all functions and macros
- Include type declarations for critical code

### Documentation
- Update relevant documentation with changes
- Include docstrings for all public functions
- Update .goosenotes with design decisions
- Keep README.md current

### Testing
- Include tests for new functionality
- Ensure existing tests pass
- Test in both virtual and bare metal environments
- Document test procedures

## Pull Request Process

1. Update documentation to reflect changes
2. Update tests appropriately
3. Ensure all tests pass
4. Update the changelog
5. Submit PR with clear description
6. Respond to review comments

## Code of Conduct

### Our Standards
- Be respectful and inclusive
- Focus on technical merit
- Accept constructive criticism
- Help others learn and grow

### Unacceptable Behavior
- Harassment or discrimination
- Destructive criticism
- Disruptive behavior
- Non-constructive feedback

## Security Issues

- Report security issues privately
- Include detailed reproduction steps
- Provide impact assessment
- Allow time for fixes before disclosure

## License

By contributing to Modus, you agree that your contributions will be licensed under its MIT License.