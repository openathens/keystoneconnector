This repository is forked from the .NET Foundation [Katana project](https://github.com/aspnet/AspNetKatana), to provide an Owin-based OpenID Connect library that is compatible with OpenAthens Keystone.

The compiled library is available as the Nuget Package [OpenAthens.Owin.Security.OpenIdConnect](https://www.nuget.org/packages/OpenAthens.Owin.Security.OpenIdConnect), which is intended to be used as a drop-in replacement for Microsoft.Owin.Security.OpenIdConnect, which is not compatible with OpenAthens.

Original documentation is available in the [Katana wiki](https://github.com/aspnet/AspNetKatana/wiki) and overview of [OWIN and Katana](https://docs.microsoft.com/en-us/aspnet/aspnet/overview/owin-and-katana/).

## Build for local use
To build for local use, simply open and build the Visual Studio solution in Debug mode

## Build NuGet package for release
The Release build requires a strong naming key pair and is intended only for the repository owner.
