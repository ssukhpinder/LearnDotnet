# Certificate Pinning Authentication Sample

## Purpose

This sample demonstrates **Certificate Pinning** (also known as SSL/TLS Pinning), a security technique that validates server certificates against a predefined set of trusted certificate fingerprints. This prevents man-in-the-middle attacks by ensuring your application only accepts connections from servers with known, trusted certificates.

## What is Certificate Pinning?

Certificate pinning is a security mechanism where an application validates that a server's certificate matches a pre-configured "pinned" certificate or public key. Instead of trusting any certificate signed by a Certificate Authority (CA), the application only trusts specific certificates it has been configured to accept.

## Key Features

- **Certificate Validation**: Validates server certificates against pinned thumbprints
- **Custom HTTP Client**: Demonstrates secure HTTP connections with certificate validation
- **Certificate Management**: Add new certificates to the pinned list
- **Logging**: Comprehensive logging of certificate validation attempts

## Setup Instructions

### Prerequisites
- .NET 9.0 SDK or later
- Visual Studio 2022 or VS Code

### Build and Run

1. **Navigate to the project directory:**
   ```bash
   cd samples/certificate-pinning-authentication/CertificatePinningAuthSample
   ```

2. **Restore dependencies:**
   ```bash
   dotnet restore
   ```

3. **Build the project:**
   ```bash
   dotnet build
   ```

4. **Run the application:**
   ```bash
   dotnet run
   ```

5. **Access the API:**
   - Base URL: `https://localhost:7001`
   - API Info: `https://localhost:7001/api/certificate/info`

## Example Usage

### 1. Get API Information
```bash
curl https://localhost:7001/api/certificate/info
```

**Expected Output:**
```json
{
  "message": "Certificate Pinning Authentication Sample",
  "description": "This API demonstrates certificate pinning for secure connections",
  "endpoints": [
    "GET /api/certificate/validate/{url} - Validate a URL against pinned certificates",
    "POST /api/certificate/pin - Pin a new certificate thumbprint",
    "GET /api/certificate/info - Get API information"
  ]
}
```

### 2. Validate a URL (Success Case)
```bash
curl https://localhost:7001/api/certificate/validate/github.com
```

**Expected Output (if certificate is pinned):**
```json
{
  "url": "github.com",
  "status": "Certificate validation passed",
  "statusCode": 200
}
```

### 3. Validate a URL (Failure Case)
```bash
curl https://localhost:7001/api/certificate/validate/example.com
```

**Expected Output (if certificate is not pinned):**
```json
{
  "url": "example.com",
  "status": "Certificate validation failed",
  "error": "Certificate validation failed"
}
```

### 4. Pin a New Certificate
```bash
curl -X POST https://localhost:7001/api/certificate/pin \
  -H "Content-Type: application/json" \
  -d '{"thumbprint": "A1B2C3D4E5F6789012345678901234567890ABCD"}'
```

**Expected Output:**
```json
{
  "status": "Certificate pinned successfully",
  "thumbprint": "A1B2C3D4E5F6789012345678901234567890ABCD"
}
```

## How It Works

1. **Certificate Validation**: The `CertificatePinningService` maintains a list of trusted certificate thumbprints
2. **HTTP Client Configuration**: Custom `HttpClientHandler` with certificate validation callback
3. **Thumbprint Comparison**: Server certificates are validated against the pinned thumbprint list
4. **Secure Connections**: Only connections to servers with pinned certificates are allowed

## Security Benefits

- **Prevents MITM Attacks**: Blocks connections to servers with untrusted certificates
- **Enhanced Security**: Goes beyond standard CA validation
- **Attack Surface Reduction**: Limits trust to specific, known certificates
- **Compliance**: Helps meet security requirements for sensitive applications

## Important Notes

- **Certificate Rotation**: Update pinned certificates when servers rotate their certificates
- **Backup Pins**: Consider pinning backup certificates to prevent service disruption
- **Testing**: Thoroughly test certificate pinning in staging environments
- **Monitoring**: Monitor certificate expiration dates and plan for updates

## Production Considerations

- Store pinned certificates securely (e.g., Azure Key Vault, environment variables)
- Implement certificate rotation strategies
- Use multiple pinned certificates for redundancy
- Monitor certificate validation logs for security incidents