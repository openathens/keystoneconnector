This repository is forked from the .NET Foundation [Katana project](https://github.com/aspnet/AspNetKatana), to provide a stand-alone Owin-based OpenId Connect library compatible with OpenAthens Keystone.

Original documentation is available in the [Katana wiki](https://github.com/aspnet/AspNetKatana/wiki) and overview of [OWIN and Katana](https://docs.microsoft.com/en-us/aspnet/aspnet/overview/owin-and-katana/).

## Build for local use
To build for local use, simply open and build the Visual Studio solution

## Build NuGet package for release
* Update both AssemblyVersion and AssemblyInformationalVersion in AssessmblyInfo.cs
* Build solution in Release mode
* Build NuGet package via .csproj rather than directly via .nuspec file (this ensures variable substitution into nuspec file):
`nuget.exe pack src\OpenAthens.Owin.Security.OpenIdConnect\OpenAthens.Owin.Security.OpenIdConnect.csproj -Prop Configuration=Release`