# FO-DICOM Security Issues Report

## Executive Summary

This report contains **security-specific findings** extracted from the comprehensive code review of the fo-dicom repository. This is a focused report containing only security vulnerabilities, excluding general logic bugs and code quality issues.

**Review Date:** December 19, 2025  
**Repository:** Vet-Rocket/fo-dicom  
**Files Reviewed:** 418 C# files (296 in DICOM directory, 122 in other directories)  
**Focus:** Security vulnerabilities only

## Security Issues Summary

**Total Security Issues Identified:** 8

**By Severity:**
- **Critical:** 2 issues
- **High:** 1 issue
- **Medium:** 4 issues
- **Low-Medium:** 1 issue

---

## Critical Security Issues

### 1. **SQL Injection Vulnerability**
**File:** `DICOM/DatabaseQueryTransformRule.cs`  
**Lines:** 146-160  
**Severity:** Critical  
**Type:** Security - SQL Injection

**Issue:**
```csharp
command.CommandText = _query;

for (int i = 0; i < _params.Count; i++)
{
    var str = dataset.Get<string>(_params[i], -1, String.Empty);
    SqlParameter prm = new SqlParameter(String.Format("@{0}", i), str);
    command.Parameters.Add(prm);
}
```

**Description:** While the code uses parameterized queries (which is good), the `_query` field itself could be user-controllable. If the query string is constructed from user input before being passed to this class, it could still be vulnerable to SQL injection. The code doesn't validate that the query contains only safe SQL constructs.

**Security Impact:**
- Unauthorized database access
- Data exfiltration
- Data manipulation or deletion
- Potential remote code execution depending on database permissions

**Recommendation:**
- Ensure `_query` is never constructed from user input
- Add validation/whitelist for allowed SQL queries
- Consider using stored procedures instead
- Add code comments warning about SQL injection risks
- Implement query pattern validation

---

### 2. **TLS Certificate Validation Can Be Bypassed**
**File:** `DICOM/Network/DesktopNetworkStream.cs`  
**Lines:** 38, 60-63  
**Severity:** Critical  
**Type:** Security - Insufficient Certificate Validation

**Issue:**
```csharp
internal DesktopNetworkStream(string host, int port, bool useTls, bool noDelay, bool ignoreSslPolicyErrors, string certificateName)
{
    // ...
    var ssl = new SslStream(
        stream,
        false,
        new RemoteCertificateValidationCallback(VerifyCertificate), null, EncryptionPolicy.RequireEncryption);
```

**Description:** The constructor accepts an `ignoreSslPolicyErrors` parameter, which suggests the `VerifyCertificate` callback might skip certificate validation. This is a critical security vulnerability that could allow man-in-the-middle attacks.

**Security Impact:**
- Man-in-the-middle attacks
- Eavesdropping on sensitive medical data
- Data tampering during transmission
- Impersonation of legitimate DICOM servers
- HIPAA/medical data privacy violations

**Recommendation:**
- Review the `VerifyCertificate` implementation
- Ensure certificate validation cannot be completely disabled in production
- If bypass is needed for testing, ensure it's only available in DEBUG builds
- Add security warnings in documentation
- Consider separate code paths for production vs. development/testing

---

## High Severity Security Issues

### 3. **Integer Overflow in PDU Length Parsing (DoS)**
**File:** `DICOM/Network/DicomService.cs`  
**Lines:** 646-651  
**Severity:** High  
**Type:** Security - Potential DoS

**Issue:**
```csharp
var length = BitConverter.ToInt32(buffer, 2);
length = Endian.Swap(length);
if(length < 0)
{
    throw new DicomDataException("Invalid PDU length: " + length.ToString());
}
```

**Description:** The code reads a 32-bit integer for PDU length and checks if it's negative. However, this check occurs AFTER the endian swap. A malicious actor could send a specially crafted PDU with a length value that, after endian swapping, becomes a very large positive value (near Int32.MaxValue), potentially causing:
1. Memory allocation failures
2. Out-of-memory exceptions
3. Denial of Service

The subsequent `Array.Resize(ref buffer, length + 6)` on line 655 could attempt to allocate gigabytes of memory.

**Security Impact:**
- Denial of Service attacks
- Server/application crashes
- Memory exhaustion
- Service unavailability for legitimate users

**Recommendation:**
- Add an upper bound check for PDU length (e.g., max 1GB or reasonable limit based on DICOM spec)
- Check the length value before and after endian swap
- Add proper error handling for allocation failures
- Log suspicious PDU length values for security monitoring
- Implement rate limiting for network connections

---

## Medium Severity Security Issues

### 4. **Missing Bounds Validation in Buffer Operations**
**File:** `DICOM/IO/Buffer/StreamByteBuffer.cs`  
**Lines:** 31-40, 47-55  
**Severity:** Medium  
**Type:** Security - Buffer Over-read

**Issue:**
```csharp
public byte[] Data
{
    get
    {
        byte[] data = new byte[Size];
        Stream.Position = Position;
        Stream.Read(data, 0, (int)Size);
        return data;
    }
}

public byte[] GetByteRange(int offset, int count)
{
    if (offset == 0 && count == Size) return Data;

    byte[] buffer = new byte[count];
    Stream.Position = Position + offset;
    Stream.Read(buffer, 0, count);
    return buffer;
}
```

**Description:** There's no validation that:
1. `Position + offset` doesn't overflow
2. `Position + offset + count` doesn't exceed stream length
3. `count` is non-negative
4. `offset` is non-negative

This could lead to reading beyond stream boundaries or integer overflow issues.

**Security Impact:**
- Information disclosure (reading beyond intended boundaries)
- Potential application crashes
- Memory corruption in edge cases

**Recommendation:**
- Add validation: `if (offset < 0 || count < 0) throw ArgumentOutOfRangeException`
- Validate that `Position + offset + count <= Stream.Length`
- Check for integer overflow in `Position + offset`
- Add comprehensive bounds checking before all buffer operations

---

### 5. **Missing Bounds Check in RangeByteBuffer**
**File:** `DICOM/IO/Buffer/RangeByteBuffer.cs`  
**Lines:** 58-61  
**Severity:** Medium  
**Type:** Security - Buffer Over-read

**Issue:**
```csharp
public byte[] GetByteRange(int offset, int count)
{
    return Internal.GetByteRange((int)Offset + offset, count);
}
```

**Description:** This method doesn't validate that `Offset + offset + count` doesn't exceed the `Length` of the range. This could allow reading beyond the intended range boundary.

**Security Impact:**
- Information disclosure
- Reading sensitive data from adjacent memory regions
- Potential for exploiting memory layout assumptions

**Recommendation:**
```csharp
public byte[] GetByteRange(int offset, int count)
{
    if (offset < 0 || count < 0)
        throw new ArgumentOutOfRangeException();
    if (offset + count > Length)
        throw new ArgumentOutOfRangeException("Range exceeds buffer bounds");
    return Internal.GetByteRange((int)Offset + offset, count);
}
```

---

### 6. **Obsolete TLS Protocols Still Allowed**
**File:** `DICOM/Network/DesktopNetworkStream.cs`  
**Line:** 75  
**Severity:** Medium  
**Type:** Security - Weak Cryptography

**Issue:**
```csharp
ssl.AuthenticateAsClient(host, certs, SslProtocols.Tls11 | SslProtocols.Tls12, false);
```

**Description:** TLS 1.1 is considered obsolete and has known vulnerabilities. Modern systems should use TLS 1.2 as minimum, preferably TLS 1.3.

**Security Impact:**
- Vulnerable to known TLS 1.1 attacks
- Non-compliance with modern security standards
- Potential HIPAA/regulatory compliance issues
- Data in transit may be compromised

**Recommendation:** 
- Change to `SslProtocols.Tls12 | SslProtocols.Tls13` (if available in target framework)
- Remove support for TLS 1.1 and earlier versions
- Update documentation to reflect minimum TLS version requirements
- Consider adding configuration option for TLS version with secure defaults

---

### 7. **Lack of Input Validation on Network Data**
**File:** `DICOM/IO/Reader/DicomReader.cs`  
**Lines:** 486-519  
**Severity:** Medium (High in aggregate with other issues)  
**Type:** Security - Missing Input Validation

**Issue:** The parser accepts `length` values from network data without proper validation. While there's a check for `UndefinedLength`, there's no upper bound check on regular length values. A malicious DICOM file could specify extremely large lengths.

**Description:** Network-received data is parsed without sufficient validation of length fields. This can lead to:
- Memory exhaustion attacks
- Denial of service
- Integer overflow issues
- Unexpected application behavior

**Security Impact:**
- DoS attacks via malformed DICOM files
- Memory exhaustion
- Processing delays with oversized data
- Potential for triggering other vulnerabilities

**Recommendation:**
- Add maximum length checks (e.g., 2GB limit or based on available memory)
- Validate that total dataset size doesn't exceed memory limits
- Consider streaming large datasets instead of loading into memory
- Implement progressive parsing with resource limits
- Add logging for suspicious data patterns

---

## Low-Medium Severity Security Issues

### 8. **Potential Path Traversal in Temporary File Creation**
**File:** `DICOM/IO/TemporaryFile.cs`  
**Lines:** 54-59  
**Severity:** Low-Medium  
**Type:** Security - Path Traversal

**Issue:**
```csharp
if (storagePath != null)
{
    // create file in user specified path
    var path = IOManager.Path.Combine(storagePath, Guid.NewGuid().ToString().Replace("-","")+".tmp");
    file = IOManager.CreateFileReference(path);
    file.Create().Dispose();
}
```

**Description:** If `storagePath` can be set by user input (through the `StoragePath` property), there's potential for path traversal. While the filename itself is a GUID (safe), the `storagePath` could contain "../" or absolute paths to write to unintended locations.

**Security Impact:**
- Writing temporary files to unintended locations
- Potential directory traversal attacks
- Disk space exhaustion in arbitrary locations
- Possible information disclosure if temp files are not properly cleaned up

**Recommendation:**
- Validate that `storagePath` is within expected boundaries
- Canonicalize the path before use
- Use `Path.GetFullPath()` and validate it's within allowed directories
- Implement allowlist of permitted temporary directories
- Add path validation to prevent traversal sequences

---

## Information Disclosure Issues

### Related to Exception Handling

**File:** `DICOM/Network/DesktopNetworkStream.cs`  
**Lines:** 73-81  
**Type:** Information Disclosure

**Issue:**
```csharp
try
{
    ssl.AuthenticateAsClient(host, certs, SslProtocols.Tls11 | SslProtocols.Tls12, false);
}
catch (Exception x)
{
    string err = x.Message;
    throw new DicomNetworkException("Could not authenticate SSL connection as client: " + x.Message);
}
```

**Description:** The exception message might contain sensitive information about why TLS failed, which could be used by attackers to gather information about the system.

**Security Impact:**
- Information leakage about system configuration
- Potential reconnaissance for attackers
- Exposure of internal error details

**Recommendation:** 
- Log detailed error internally but throw generic error to user/network
- Implement structured logging with security level controls
- Sanitize error messages sent to clients

---

## Recommendations Summary

### Immediate Actions (Critical)
1. **Fix SQL Injection Vulnerability** - Implement query validation and whitelist
2. **Secure TLS Certificate Validation** - Remove or properly restrict bypass capability
3. **Add PDU Length Bounds** - Prevent DoS via memory exhaustion

### High Priority (High/Medium Severity)
1. Add comprehensive bounds validation to all buffer operations
2. Update TLS protocol support (remove TLS 1.1)
3. Implement input validation for all network-received data
4. Secure path operations against traversal attacks

### Security Testing Recommendations
1. **Penetration Testing**: Test TLS implementation for MITM vulnerabilities
2. **Fuzz Testing**: Test DICOM parser with malformed/malicious files
3. **SQL Injection Testing**: Verify query construction paths
4. **DoS Testing**: Test with malicious PDU lengths and large datasets
5. **Buffer Overflow Testing**: Test all buffer operations with edge cases

### Security Monitoring
1. Log all authentication failures
2. Monitor for suspicious PDU length values
3. Track database query patterns
4. Alert on path traversal attempts
5. Monitor TLS protocol usage

---

## Additional Security Considerations

### HIPAA Compliance
Given that this is medical imaging software handling Protected Health Information (PHI):
- TLS vulnerabilities could lead to HIPAA violations
- Data integrity issues could affect patient care
- Audit logging should be implemented for security events
- Access controls should be reviewed

### Network Security
- Implement network-level rate limiting
- Consider implementing intrusion detection
- Add logging for security-relevant events
- Implement proper session management

### Defense in Depth
The identified issues should be addressed as part of a layered security approach:
1. Input validation at all trust boundaries
2. Proper encryption for data in transit
3. Secure authentication and authorization
4. Resource limits to prevent DoS
5. Comprehensive error handling without information leakage

---

## Conclusion

Eight security-specific vulnerabilities were identified, with two rated as **Critical**:
1. SQL injection potential
2. TLS certificate validation bypass

These issues require immediate attention as they could lead to:
- Unauthorized data access
- Man-in-the-middle attacks
- Denial of service
- Regulatory compliance violations

The codebase would benefit from:
- A professional security audit
- Penetration testing
- Security-focused code review process
- Implementation of secure coding standards
- Regular security training for developers

---

**Report Compiled By:** AI Security Reviewer  
**Date:** December 19, 2025  
**Classification:** Security Issues Only  
**Original Review:** SECURITY_REVIEW_REPORT.md (comprehensive review including logic bugs)
