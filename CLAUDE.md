# DG SIEM: notes for AI coding sessions

- .NET 10, C#, central package management (`Directory.Packages.props`). Add package versions there, not in csproj files.
- `TreatWarningsAsErrors` is on. Use `[LoggerMessage]` source-generated logging, not `logger.LogX(...)`.
- Event data goes to ClickHouse only; metadata to PostgreSQL only.
- Field names are ECS. Use `EcsField` constants; columns are `EcsField.ToColumn(name)`.
- Every query MUST be scoped to `QueryRequest.TenantIds` in the compiler. Never build SQL by concatenating user input; use parameters.
- ClickHouse schema changes are new numbered files in `src/DreaminGeek.Siem.Storage.ClickHouse/Migrations/` (never edit an applied one). Use `{db}` for the database name.
- Postgres schema changes: `dotnet ef migrations add <Name> -p src/DreaminGeek.Siem.Data -s src/DreaminGeek.Siem.Web -o Migrations`.
- Build/test: `dotnet build DreaminGeek.Siem.slnx && dotnet test DreaminGeek.Siem.slnx`.
- The agent (`DreaminGeek.Siem.Agent`) ships as Native AOT: no reflection-based JSON. Serialize agent wire types through `AgentJsonContext` in Core, and check `dotnet publish src/DreaminGeek.Siem.Agent -c Release -r linux-x64` stays warning-free.
- The agent API (`/api/v1/agent*`) is served only on the agent port (mTLS); the UI and everything else only on the HTTP port. Keep that split in `Program.cs`.
- Admin CLI (`AdminCli.cs`) is the management surface until the admin UI exists: `dg-siem-server tenant|token|agent ...`.
- Query engine: `PipeParser` (text → AST) and `ClickHouseCompiler` (AST → SQL). Add tests in `QueryTests.cs`, and when SQL changes, validate it against real ClickHouse; chDB (`pip install chdb`) works in sandboxes without Docker.
