# Contributing to FlowSentrix

Thank you for your interest in contributing to FlowSentrix! We welcome contributions from the community. This document provides guidelines and instructions for contributing to the project.

## Code of Conduct

Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing. We are committed to providing a welcoming and inclusive environment for all contributors.

## How to Contribute

### Reporting Bugs

Before reporting a bug, please:
1. Check the [existing issues](https://github.com/DamodarPatil/FlowSentrix/issues) to avoid duplicates
2. Check the [documentation](https://github.com/DamodarPatil/FlowSentrix/wiki)
3. Verify the issue on the latest version

When reporting a bug, please use the [Bug Report issue template](https://github.com/DamodarPatil/FlowSentrix/issues/new?template=bug_report.md) and include:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, FlowSentrix version)
- Relevant logs or error messages

### Requesting Features

To request a feature, use the [Feature Request issue template](https://github.com/DamodarPatil/FlowSentrix/issues/new?template=feature_request.md) and include:
- Clear description of the feature
- Use case and why it's needed
- Proposed implementation (optional)
- Any alternative approaches you've considered

### Submitting Pull Requests

1. **Fork the Repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/FlowSentrix.git
   cd FlowSentrix
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or for bugfixes
   git checkout -b fix/your-bug-name
   ```

3. **Set Up Development Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # if available
   ```

4. **Make Your Changes**
   - Follow the code style and conventions used in the project
   - Write clear, descriptive commit messages
   - Test your changes thoroughly
   - Add comments for complex logic

5. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "type: brief description

   Longer description of the changes if needed.
   Explain why the change is needed and how it solves the problem.
   
   Fixes #issue_number (if applicable)
   ```

6. **Push to Your Fork**
   ```bash
   git push origin your-branch-name
   ```

7. **Create a Pull Request**
   - Use the [Pull Request template](pull_request_template.md)
   - Provide a clear title and description
   - Reference any related issues
   - Ensure all checks pass

## Development Guidelines

### Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guidelines
- Use meaningful variable and function names
- Write docstrings for functions and classes
- Keep functions focused and single-purpose

### Testing

- Write tests for new features
- Ensure existing tests pass: `python -m pytest`
- Aim for good test coverage
- Test edge cases and error scenarios

### Documentation

- Update README.md if adding new features
- Add docstrings to new code
- Update wiki pages if applicable
- Keep changes documented in commit messages

### Commit Messages

Follow conventional commits format:
```
type(scope): subject

body

footer
```

**Types:**
- `feat:` A new feature
- `fix:` A bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `test:` Adding or updating tests
- `chore:` Other changes (dependencies, build, etc.)

**Example:**
```
feat(sniffer): add packet filtering by protocol

Added ability to filter captured packets by protocol type.
Users can now specify protocol in configuration file.

Fixes #123
```

## Review Process

1. Your PR will be reviewed by maintainers
2. Address feedback and make requested changes
3. Once approved, your PR will be merged
4. Your contribution will be acknowledged

## Community and Support

- **Discussions:** [GitHub Discussions](https://github.com/DamodarPatil/FlowSentrix/discussions)
- **Issues:** [GitHub Issues](https://github.com/DamodarPatil/FlowSentrix/issues)
- **Documentation:** [Wiki](https://github.com/DamodarPatil/FlowSentrix/wiki)

## Legal

By contributing to FlowSentrix, you agree that your contributions will be licensed under the same license as the project.

## Thank You

We appreciate your contribution to making FlowSentrix better! 🎉
