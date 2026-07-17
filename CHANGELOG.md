# Changelog

All notable changes to this repository are documented in this file.

## [Unreleased]

### Fixed
- **Package license metadata now consistent (Apache-2.0).** `Andy.Auth` previously
  declared `MIT` in its `.nuspec` while the repository `LICENSE`, `README`, and
  `Directory.Build.props` all state Apache-2.0. The per-project MIT override was
  removed so every package inherits Apache-2.0 from `Directory.Build.props`.
  A redundant Apache-2.0 override in `Andy.Auth.M2MClient` was also removed.
  Published NuGet packages now carry `<license type="expression">Apache-2.0</license>`.

### Changed
- **Introduced Central Package Management (CPM).** Added a root
  `Directory.Packages.props`; all `PackageReference` version numbers moved there and
  were stripped from the individual `.csproj` files. Test and shared tooling versions
  are now unified across every test project:
  - `Microsoft.NET.Test.Sdk` → 17.12.0 (was 17.8.0 / 17.11.1 / 17.12.0)
  - `xunit` → 2.9.2 (was 2.5.3 / 2.9.2)
  - `xunit.runner.visualstudio` → 2.8.2 (was 2.5.3 / 2.8.2)
  - `Moq` → 4.20.72 (was 4.20.70 / 4.20.72)
  - `coverlet.collector` → 6.0.2 (was 6.0.0 / 6.0.2)
- **Pinned FluentAssertions to 6.12.0** (the last Apache-2.0 / free release) across
  all test projects. `Andy.Auth.Tests` had been on 8.8.0, which carries a commercial
  (Xceed) license and emits a licensing warning. Only classic `.Should()` APIs are
  used, so 6.x is a drop-in replacement and the warning is eliminated.

### Added
- CI now validates package metadata before publishing: the `Build and Release`
  workflow inspects each packed `.nupkg` and fails if it does not declare the
  Apache-2.0 license or is missing its readme.
