# Software Bill of Materials (SBOM)

## Project Information

- **Name:** fo-dicom (Fellow Oak DICOM)
- **Version:** 3.0.0.30
- **License:** Microsoft Public License (MS-PL)
- **Copyright:** Copyright (c) 2012-2025 fo-dicom contributors
- **Description:** Fellow Oak DICOM for .NET, .NET Core, Universal Windows, Android, iOS, Mono and Unity
- **Homepage:** https://github.com/fo-dicom/fo-dicom
- **Repository:** https://github.com/Vet-Rocket/fo-dicom

## SBOM Formats

This project provides Software Bill of Materials in multiple standard formats:

- **SBOM.spdx** - SPDX 2.3 format (ISO/IEC 5962:2021 standard)
- **SBOM.json** - CycloneDX 1.4 format (JSON)
- **SBOM.md** - Human-readable Markdown format (this file)

## Dependencies Summary

### Statistics

- **Total Dependencies:** 29 packages (24 NuGet + 5 embedded native libraries)
- **Direct Dependencies:** 16 packages
- **Test Dependencies:** 7 packages (xunit ecosystem)
- **Optional Dependencies:** 1 package (UWP platform)
- **Embedded Native Libraries:** 5 libraries

### License Distribution

| License Type | Count | Packages |
|--------------|-------|----------|
| MIT | 11 | Newtonsoft.Json, MetroLog, NETStandard.Library, System.* (7 packages) |
| Apache-2.0 | 9 | log4net, Serilog, xunit (7 packages) |
| BSD-3-Clause | 3 | Portable.LibJpeg.NET, NLog, CharLS |
| BSD-2-Clause | 2 | CSJ2K, OpenJPEG |
| IJG License | 3 | libijg-8bit, libijg-12bit, libijg-16bit |

All licenses are permissive open-source licenses compatible with commercial use.

## Direct Dependencies

### Image Codec Libraries

#### CSJ2K
- **Version:** 2.0.0.1
- **License:** BSD-2-Clause
- **Purpose:** JPEG 2000 image compression/decompression
- **Package URL:** pkg:nuget/CSJ2K@2.0.0.1

#### Portable.LibJpeg.NET
- **Version:** 1.5.1.1
- **License:** BSD-3-Clause
- **Purpose:** JPEG image compression/decompression (managed implementation)
- **Package URL:** pkg:nuget/Portable.LibJpeg.NET@1.5.1.1

### Serialization Libraries

#### Newtonsoft.Json
- **Version:** 9.0.1
- **License:** MIT
- **Purpose:** JSON serialization/deserialization for DICOM data
- **Package URL:** pkg:nuget/Newtonsoft.Json@9.0.1
- **Copyright:** Copyright (c) 2007 James Newton-King

### Logging Libraries

#### NLog
- **Version:** 4.4.1
- **License:** BSD-3-Clause
- **Purpose:** Logging framework integration
- **Package URL:** pkg:nuget/NLog@4.4.1
- **Copyright:** Copyright (c) 2004-2017 Jaroslaw Kowalski, Kim Christensen, Julian Verdurmen

#### log4net
- **Version:** 2.0.7
- **License:** Apache-2.0
- **Purpose:** Logging framework integration (alternative)
- **Package URL:** pkg:nuget/log4net@2.0.7
- **Copyright:** Copyright 2004-2017 The Apache Software Foundation

#### Serilog
- **Version:** 2.3.0
- **License:** Apache-2.0
- **Purpose:** Structured logging framework integration
- **Package URL:** pkg:nuget/Serilog@2.3.0
- **Copyright:** Copyright 2013-2016 Serilog Contributors

#### MetroLog
- **Version:** 1.0.1
- **License:** MIT
- **Purpose:** Logging framework for portable class libraries
- **Package URL:** pkg:nuget/MetroLog@1.0.1

### .NET Core Libraries

#### NETStandard.Library
- **Version:** 1.6.1
- **License:** MIT
- **Purpose:** .NET Standard base class libraries
- **Package URL:** pkg:nuget/NETStandard.Library@1.6.1
- **Copyright:** Copyright (c) .NET Foundation and Contributors

#### System.Data.SqlClient
- **Version:** 4.3.0
- **License:** MIT
- **Purpose:** SQL Server database connectivity
- **Package URL:** pkg:nuget/System.Data.SqlClient@4.3.0

#### System.IO.FileSystem
- **Version:** 4.3.0
- **License:** MIT
- **Purpose:** File system access APIs
- **Package URL:** pkg:nuget/System.IO.FileSystem@4.3.0

#### System.Net.NetworkInformation
- **Version:** 4.3.0
- **License:** MIT
- **Purpose:** Network information APIs
- **Package URL:** pkg:nuget/System.Net.NetworkInformation@4.3.0

#### System.Net.Security
- **Version:** 4.3.0
- **License:** MIT
- **Purpose:** Network security APIs
- **Package URL:** pkg:nuget/System.Net.Security@4.3.0

#### System.Runtime.Serialization.Primitives
- **Version:** 4.3.0
- **License:** MIT
- **Purpose:** Serialization primitives
- **Package URL:** pkg:nuget/System.Runtime.Serialization.Primitives@4.3.0

#### System.Runtime.Numerics
- **Version:** 4.3.0
- **License:** MIT
- **Purpose:** Numeric types (BigInteger, etc.)
- **Package URL:** pkg:nuget/System.Runtime.Numerics@4.3.0

#### System.Threading.Tasks.Parallel
- **Version:** 4.3.0
- **License:** MIT
- **Purpose:** Parallel programming APIs
- **Package URL:** pkg:nuget/System.Threading.Tasks.Parallel@4.3.0

## Test Dependencies

The following dependencies are only used during development and testing:

### xunit Framework

#### xunit
- **Version:** 2.1.0
- **License:** Apache-2.0
- **Purpose:** Main xUnit testing framework package
- **Package URL:** pkg:nuget/xunit@2.1.0

#### xunit.abstractions
- **Version:** 2.0.0
- **License:** Apache-2.0
- **Purpose:** xUnit abstractions
- **Package URL:** pkg:nuget/xunit.abstractions@2.0.0

#### xunit.assert
- **Version:** 2.1.0
- **License:** Apache-2.0
- **Purpose:** xUnit assertion library
- **Package URL:** pkg:nuget/xunit.assert@2.1.0

#### xunit.core
- **Version:** 2.1.0
- **License:** Apache-2.0
- **Purpose:** xUnit core library
- **Package URL:** pkg:nuget/xunit.core@2.1.0

#### xunit.extensibility.core
- **Version:** 2.1.0
- **License:** Apache-2.0
- **Purpose:** xUnit extensibility core
- **Package URL:** pkg:nuget/xunit.extensibility.core@2.1.0

#### xunit.extensibility.execution
- **Version:** 2.1.0
- **License:** Apache-2.0
- **Purpose:** xUnit extensibility execution
- **Package URL:** pkg:nuget/xunit.extensibility.execution@2.1.0

#### xunit.runner.visualstudio
- **Version:** 2.1.0
- **License:** Apache-2.0
- **Purpose:** Visual Studio test runner for xUnit
- **Package URL:** pkg:nuget/xunit.runner.visualstudio@2.1.0

All xunit packages are copyright (c) .NET Foundation and Contributors.

## Optional Dependencies

### Universal Windows Platform

#### Microsoft.NETCore.UniversalWindowsPlatform
- **Version:** 5.2.2
- **License:** MIT
- **Purpose:** UWP platform support (only used when building UWP applications)
- **Package URL:** pkg:nuget/Microsoft.NETCore.UniversalWindowsPlatform@5.2.2
- **Scope:** Optional (platform-specific)

## Embedded Native Libraries

These libraries are included as source code within the project:

### libijg (Independent JPEG Group Library)

Three variants of the IJG JPEG library are embedded:

#### libijg-8bit
- **Version:** Embedded source
- **License:** IJG License (BSD-like permissive)
- **Purpose:** 8-bit JPEG compression/decompression
- **Location:** DICOM.Native/libijg8/
- **Copyright:** Copyright (C) 1991-1998, Thomas G. Lane
- **CPE:** cpe:2.3:a:ijg:libjpeg:*:*:*:*:*:*:*:*

#### libijg-12bit
- **Version:** Embedded source
- **License:** IJG License (BSD-like permissive)
- **Purpose:** 12-bit JPEG compression/decompression
- **Location:** DICOM.Native/libijg12/
- **Copyright:** Copyright (C) 1991-1998, Thomas G. Lane
- **CPE:** cpe:2.3:a:ijg:libjpeg:*:*:*:*:*:*:*:*

#### libijg-16bit
- **Version:** Embedded source
- **License:** IJG License (BSD-like permissive)
- **Purpose:** 16-bit JPEG compression/decompression
- **Location:** DICOM.Native/libijg16/
- **Copyright:** Copyright (C) 1991-1998, Thomas G. Lane
- **CPE:** cpe:2.3:a:ijg:libjpeg:*:*:*:*:*:*:*:*

### OpenJPEG

#### OpenJPEG
- **Version:** Embedded source
- **License:** BSD-2-Clause
- **Purpose:** JPEG 2000 compression/decompression (lossless and lossy)
- **Location:** DICOM.Native/OpenJPEG/
- **Copyright:** 
  - Copyright (c) 2002-2007, Communications and Remote Sensing Laboratory, UCL, Belgium
  - Copyright (c) 2002-2007, Professor Benoit Macq
  - Copyright (c) 2001-2003, David Janssens
  - Copyright (c) 2002-2003, Yannick Verschueren
  - Copyright (c) 2003-2007, Francois-Olivier Devaux and Antonin Descampe
  - Copyright (c) 2005, Herve Drolon, FreeImage Team
- **CPE:** cpe:2.3:a:uclouvain:openjpeg:*:*:*:*:*:*:*:*

### CharLS

#### CharLS
- **Version:** Embedded source
- **License:** BSD-3-Clause
- **Purpose:** JPEG-LS compression/decompression (lossless/near-lossless)
- **Location:** DICOM.Native/CharLS/
- **Copyright:** Copyright (c) 2007-2009, Jan de Vaan
- **CPE:** cpe:2.3:a:charls:charls:*:*:*:*:*:*:*:*

## License Compliance

### Summary

All dependencies use permissive open-source licenses that:
- Allow commercial use
- Allow modification and redistribution
- Do not impose copyleft restrictions
- Are compatible with the MS-PL license of fo-dicom

### License Texts

Full license texts for the main project and embedded libraries are available in:
- **License.txt** - Contains MS-PL, IJG License, OpenJPEG BSD license, and CharLS BSD license
- **SBOM.spdx** - Contains extracted license texts for MS-PL and IJG licenses

### Attribution Requirements

To comply with dependency licenses:

1. **MIT/BSD Licensed packages:** Retain copyright notices (satisfied through package management)
2. **Apache-2.0 Licensed packages:** Retain copyright and NOTICE files (satisfied through package management)
3. **IJG License:** Acknowledge use in documentation: "This software is based in part on the work of the Independent JPEG Group"
4. **MS-PL (fo-dicom itself):** Include license with distributions

## Security Information

### CPE Identifiers

Common Platform Enumeration (CPE) identifiers for security scanning:

- **libijg (all variants):** cpe:2.3:a:ijg:libjpeg:*:*:*:*:*:*:*:*
- **OpenJPEG:** cpe:2.3:a:uclouvain:openjpeg:*:*:*:*:*:*:*:*
- **CharLS:** cpe:2.3:a:charls:charls:*:*:*:*:*:*:*:*

### Package URLs (PURL)

All components use Package URL (PURL) identifiers for standardized component identification:

- NuGet packages: `pkg:nuget/{name}@{version}`
- Embedded libraries: `pkg:generic/{name}@embedded`

## Change History

- **2026-02-18:** Initial SBOM created for version 3.0.0.30
- Includes all direct dependencies, test dependencies, and embedded native libraries
- Generated in SPDX 2.3, CycloneDX 1.4, and Markdown formats

## Additional Resources

- **Dependencies Documentation:** See DEPENDENCIES.md for detailed dependency analysis
- **Main License:** See License.txt for the fo-dicom MS-PL license and embedded library licenses
- **Source Code:** https://github.com/Vet-Rocket/fo-dicom
- **Original Project:** https://github.com/fo-dicom/fo-dicom

---

**Generated:** 2026-02-18  
**SBOM Version:** 1  
**SBOM Formats:** SPDX 2.3, CycloneDX 1.4, Markdown  
**Generator:** Manual compilation from project files
