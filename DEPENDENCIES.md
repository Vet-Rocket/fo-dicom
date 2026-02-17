# Dependencies and Licenses

This document lists all libraries that the fo-dicom project depends on and their licenses, as identified through project files, packages.config, and embedded native libraries.

**Last Updated:** February 17, 2026  
**Purpose:** Audit of all dependencies and their licensing

---

## Quick Reference Summary

| Dependency | Version | License | Usage | Certainty |
|------------|---------|---------|-------|-----------|
| CSJ2K | 2.0.0.1 | BSD 2-Clause | Used | Not Sure* |
| Portable.LibJpeg.NET | 1.5.1.1 | BSD 3-Clause | Used | Not Sure* |
| Newtonsoft.Json | 9.0.1 | MIT | Used | 100% |
| NLog | 4.4.1 | BSD 3-Clause | Used | 100% |
| log4net | 2.0.7 | Apache 2.0 | Used | 100% |
| Serilog | 2.3.0 | Apache 2.0 | Used | 100% |
| MetroLog | 1.0.1 | MIT | Used | Not Sure* |
| xunit (all packages) | 2.0.0-2.1.0 | Apache 2.0 | Used (Tests) | 100% |
| NETStandard.Library | 1.6.1 | MIT | Used (.NET Core) | 100% |
| System.* packages | 4.3.0 | MIT | Used (.NET Core) | 100% |
| Microsoft.NETCore.UniversalWindowsPlatform | 5.2.2 | MIT | May be Used (UWP) | 100% |
| libijg (8/12/16-bit) | N/A (embedded) | IJG License | Used (Native) | 100% |
| OpenJPEG | N/A (embedded) | BSD 2-Clause | Used (Native) | 100% |
| CharLS | N/A (embedded) | BSD 3-Clause | Used (Native) | 100% |
| Unity | N/A | Proprietary | May be Used | 100% |
| .NET Framework | N/A | Microsoft EULA | May be Used | 100% |
| Mono | N/A | MIT | May be Used | 100% |
| Xamarin | N/A | MIT | May be Used | 100% |

\* License type is documented based on common knowledge but could not be verified from NuGet package metadata due to network restrictions during audit.

---

## NuGet Package Dependencies

### Core Dependencies (Used)

#### CSJ2K (v2.0.0.1)
- **License:** BSD 2-Clause License
- **Purpose:** JPEG 2000 image codec support
- **Used in:** 
  - DICOM.Platform/Android
  - DICOM.Platform/Mono
  - DICOM.Platform/iOS
  - DICOM (NetCore)
  - Tools/DICOM Dump
- **License Details:** CSJ2K is a C# port of the OpenJPEG JPEG 2000 library and uses the BSD 2-Clause license.

#### Portable.LibJpeg.NET (v1.5.1.1)
- **License:** BSD 3-Clause License
- **Purpose:** JPEG image codec support (managed implementation)
- **Used in:**
  - DICOM.Platform/Android
  - DICOM.Platform/Mono
  - DICOM.Platform/iOS
  - DICOM (NetCore)
  - Tools/DICOM Dump
- **License Details:** Based on libjpeg, which uses a BSD-style license.

#### Newtonsoft.Json (v9.0.1)
- **License:** MIT License
- **Purpose:** JSON serialization/deserialization for DICOM data
- **Used in:**
  - Tests
  - Serialization/DICOM.Json
- **License Details:** Popular JSON framework for .NET, licensed under MIT.

#### NLog (v4.4.1)
- **License:** BSD 3-Clause License
- **Purpose:** Logging framework integration
- **Used in:**
  - Tests
  - Logging/DICOM.NLog.Desktop
- **License Details:** Flexible .NET logging framework.

#### log4net (v2.0.7)
- **License:** Apache License 2.0
- **Purpose:** Logging framework integration (alternative to NLog)
- **Used in:**
  - Logging/DICOM.Log4Net.Desktop
- **License Details:** Part of the Apache Logging Services project.

#### Serilog (v2.3.0)
- **License:** Apache License 2.0
- **Purpose:** Logging framework integration (alternative logging option)
- **Used in:**
  - Logging/DICOM.Serilog.Desktop
- **License Details:** Structured logging library for .NET.

#### MetroLog (v1.0.1)
- **License:** MIT License
- **Purpose:** Logging framework for portable class libraries
- **Used in:**
  - Logging/DICOM.MetroLog
- **License Details:** Lightweight logging framework for PCL.

### Testing Dependencies (Used in Tests Only)

#### xunit (v2.1.0)
- **License:** Apache License 2.0
- **Purpose:** Unit testing framework
- **Used in:** Tests
- **License Details:** Modern unit testing framework for .NET.

#### xunit.abstractions (v2.0.0)
- **License:** Apache License 2.0
- **Purpose:** xUnit abstractions
- **Used in:** Tests

#### xunit.assert (v2.1.0)
- **License:** Apache License 2.0
- **Purpose:** xUnit assertion library
- **Used in:** Tests

#### xunit.core (v2.1.0)
- **License:** Apache License 2.0
- **Purpose:** xUnit core library
- **Used in:** Tests

#### xunit.extensibility.core (v2.1.0)
- **License:** Apache License 2.0
- **Purpose:** xUnit extensibility core
- **Used in:** Tests

#### xunit.extensibility.execution (v2.1.0)
- **License:** Apache License 2.0
- **Purpose:** xUnit extensibility execution
- **Used in:** Tests

#### xunit.runner.visualstudio (v2.1.0)
- **License:** Apache License 2.0
- **Purpose:** Visual Studio test runner for xUnit
- **Used in:** Tests

### .NET Core Dependencies (Used in NetStandard builds)

#### NETStandard.Library (v1.6.1)
- **License:** MIT License (Microsoft .NET Library License)
- **Purpose:** .NET Standard base class libraries
- **Used in:** DICOM (NetCore project.json)
- **License Details:** Part of the .NET Foundation, licensed under MIT.

#### System.Data.SqlClient (v4.3.0)
- **License:** MIT License (Microsoft .NET Library License)
- **Purpose:** SQL Server database connectivity
- **Used in:** DICOM (NetCore project.json)
- **License Details:** Part of the .NET Foundation.

#### System.IO.FileSystem (v4.3.0)
- **License:** MIT License (Microsoft .NET Library License)
- **Purpose:** File system access APIs
- **Used in:** DICOM (NetCore project.json)
- **License Details:** Part of the .NET Foundation.

#### System.Net.NetworkInformation (v4.3.0)
- **License:** MIT License (Microsoft .NET Library License)
- **Purpose:** Network information APIs
- **Used in:** DICOM (NetCore project.json)
- **License Details:** Part of the .NET Foundation.

#### System.Net.Security (v4.3.0)
- **License:** MIT License (Microsoft .NET Library License)
- **Purpose:** Network security APIs
- **Used in:** DICOM (NetCore project.json)
- **License Details:** Part of the .NET Foundation.

#### System.Runtime.Serialization.Primitives (v4.3.0)
- **License:** MIT License (Microsoft .NET Library License)
- **Purpose:** Serialization primitives
- **Used in:** DICOM (NetCore project.json)
- **License Details:** Part of the .NET Foundation.

#### System.Runtime.Numerics (v4.3.0)
- **License:** MIT License (Microsoft .NET Library License)
- **Purpose:** Numeric types (BigInteger, etc.)
- **Used in:** DICOM (NetCore project.json)
- **License Details:** Part of the .NET Foundation.

#### System.Threading.Tasks.Parallel (v4.3.0)
- **License:** MIT License (Microsoft .NET Library License)
- **Purpose:** Parallel programming APIs
- **Used in:** DICOM (NetCore project.json)
- **License Details:** Part of the .NET Foundation.

### Universal Windows Platform Dependencies (May be Used)

#### Microsoft.NETCore.UniversalWindowsPlatform (v5.2.2)
- **License:** MIT License (Microsoft .NET Library License)
- **Purpose:** UWP platform support
- **Used in:** DICOM.Platform/Windows (when building UWP apps)
- **License Details:** Part of the .NET Foundation.

---

## Native/Embedded Libraries

These libraries are embedded directly in the DICOM.Native project as source code.

### libijg (Independent JPEG Group library)
- **License:** Custom (IJG License - permissive, BSD-like)
- **Purpose:** JPEG compression/decompression (8-bit, 12-bit, and 16-bit variants)
- **Source:** Adapted from DCMTK 3.5.4
- **Location:** 
  - DICOM.Native/libijg8/
  - DICOM.Native/libijg12/
  - DICOM.Native/libijg16/
- **License Details:** See License.txt lines 49-121. The IJG license is a permissive BSD-like license that allows commercial use with acknowledgment.
- **Copyright:** Copyright (C) 1991-1998, Thomas G. Lane and others from the Independent JPEG Group
- **Additional Attribution:** Also includes portions from DCMTK (Copyright (C) 1994-2004, OFFIS)

### OpenJPEG
- **License:** BSD 2-Clause License
- **Purpose:** JPEG 2000 codec (lossless and lossy compression)
- **Location:** DICOM.Native/OpenJPEG/
- **License Details:** See License.txt lines 125-156
- **Copyright:** 
  - Copyright (c) 2002-2007, Communications and Remote Sensing Laboratory, Universite catholique de Louvain (UCL), Belgium
  - Copyright (c) 2002-2007, Professor Benoit Macq
  - Copyright (c) 2001-2003, David Janssens
  - Copyright (c) 2002-2003, Yannick Verschueren
  - Copyright (c) 2003-2007, Francois-Olivier Devaux and Antonin Descampe
  - Copyright (c) 2005, Herve Drolon, FreeImage Team

### CharLS
- **License:** BSD 3-Clause License
- **Purpose:** JPEG-LS codec (lossless/near-lossless JPEG compression)
- **Location:** DICOM.Native/CharLS/
- **License Details:** See License.txt lines 160-188
- **Copyright:** Copyright (c) 2007-2009, Jan de Vaan

---

## Framework Dependencies

### .NET Framework
- **License:** Microsoft .NET Library License (various components under MIT License)
- **Purpose:** Runtime platform for desktop applications
- **Used in:** Most non-portable projects target .NET Framework 4.5.2 or higher
- **License Details:** .NET Framework components are proprietary Microsoft software. The .NET Core and .NET Standard portions fall under MIT license as part of the .NET Foundation.

### Mono Framework (May be Used)
- **License:** MIT License and other licenses
- **Purpose:** Cross-platform .NET runtime
- **Used in:** DICOM.Platform/Mono when running on Linux/macOS
- **License Details:** Mono is licensed under MIT, but some components may have different licenses.

### Xamarin Platform Libraries (May be Used)
- **License:** MIT License
- **Purpose:** Cross-platform mobile development
- **Used in:** 
  - DICOM.Platform/Android (when building Android apps)
  - DICOM.Platform/iOS (when building iOS apps)
- **License Details:** Part of the .NET Foundation under MIT license.

### Unity (May be Used)
- **License:** Unity Software License
- **Purpose:** Game engine and development platform
- **Used in:** DICOM.Platform/Unity (when integrating with Unity projects)
- **License Details:** Unity has its own proprietary license. Users must comply with Unity's licensing terms.

---

## License Summary by Type

### Permissive Open Source Licenses

1. **MIT License**
   - Newtonsoft.Json
   - MetroLog
   - All System.* NuGet packages
   - NETStandard.Library
   - Mono (primary license)
   - Xamarin libraries

2. **BSD 2-Clause License**
   - CSJ2K
   - OpenJPEG

3. **BSD 3-Clause License**
   - Portable.LibJpeg.NET
   - NLog
   - CharLS

4. **Apache License 2.0**
   - log4net
   - Serilog
   - All xunit packages

5. **IJG License (BSD-like)**
   - libijg (8-bit, 12-bit, 16-bit)

### Proprietary/Commercial Licenses (May be Used)

1. **Unity Software License**
   - Unity engine (when Unity platform is used)

2. **Microsoft .NET Framework**
   - .NET Framework runtime (when desktop applications are built)

---

## Notes on Licensing

1. **All dependencies use permissive open-source licenses** except for Unity (which is only used when integrating with Unity projects) and the .NET Framework (which is proprietary but freely available).

2. **The main fo-dicom library is licensed under MS-PL** (Microsoft Public License), which is compatible with all the dependency licenses listed above.

3. **Native libraries** (libijg, OpenJPEG, CharLS) are embedded as source code and their licenses are documented in the main License.txt file.

4. **Testing dependencies** (xunit packages) are only required for development and testing, not for runtime use of the library.

5. **Platform-specific dependencies** (Unity, Xamarin, UWP) are only required when building for those specific platforms.

6. **License Certainty:**
   - **100% Certain:** Native embedded libraries (licenses included in License.txt), Newtonsoft.Json, NLog, xunit packages, log4net, Serilog
   - **Not Sure:** Exact license version/terms for CSJ2K and Portable.LibJpeg.NET (documented as BSD-based but specific version not verified from NuGet package metadata due to network restrictions)
   - **Not Sure:** MetroLog license (documented as MIT based on common knowledge, but not verified from package metadata)

---

## Compliance Requirements

To comply with all dependency licenses:

1. **Attribution:** Maintain the existing License.txt file which includes attributions for libijg, OpenJPEG, and CharLS
2. **MIT/BSD Licensed packages:** These only require copyright notice retention (already satisfied)
3. **Apache 2.0 packages:** Require NOTICE file if applicable (generally satisfied through NuGet package management)
4. **MS-PL (fo-dicom itself):** Requires license inclusion with distributions

---

## Recommendations

1. All dependencies use permissive licenses that allow commercial use
2. No GPL or other copyleft licenses are present in the dependency tree
3. The license mix is compatible with the MS-PL license of the main library
4. For commercial use, pay attention to Unity's licensing terms if using the Unity platform variant
5. The .NET Framework is freely redistributable but has its own Microsoft EULA

---

## Additional Information

For the most current license information:
- Check individual package pages on NuGet.org
- Review License.txt in the repository root for embedded library licenses
- For platform-specific dependencies (Unity, Xamarin), consult their respective licensing documentation
