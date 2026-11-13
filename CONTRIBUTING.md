# Contributing to DG SIEM

Thanks for helping. Issues and pull requests are welcome.

- Open an issue before large changes so we can agree on the approach.
- `dotnet build DreaminGeek.Siem.slnx && dotnet test DreaminGeek.Siem.slnx` must pass; warnings are errors.
- **New log sources** are the easiest way to contribute: implement `IEventParser` in `DreaminGeek.Siem.Parsers`, map fields to ECS names, and add tests with real (sanitized) sample lines.
- By contributing you agree your work is licensed under the Apache License 2.0.
