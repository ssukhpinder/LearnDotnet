# Certificate-Based Authentication Sample

This sample demonstrates how to implement certificate-based authentication in ASP.NET Core, where clients authenticate using X.509 certificates instead of traditional username/password credentials.

## Purpose

Certificate-based authentication provides a secure way to authenticate clients using digital certificates. This method is commonly used in enterprise environments, IoT scenarios, and API-to-API communication where high security is required.

## Setup Instructions

### Prerequisites
- .NET 9.0 SDK
- OpenSSL or PowerShell (for certificate generation)

### Build and Run

1. Navigate to the project directory:
   ```bash
   cd samples/certificate-authentication/CertificateAuthSample
   ```

2. Build the project:
   ```bash
   dotnet build
   ```

3. Run the application:
   ```bash
   dotnet run
   ```

The application will start on `https://localhost:5001` and `http://localhost:5000`.

### Generate Test Certificate

Create a self-signed certificate for testing:

**Using PowerShell (Windows):**
```powershell
$cert = New-SelfSignedCertificate -Subject "CN=TestClient" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
$pwd = ConvertTo-SecureString -String "password123" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "client.pfx" -Password $pwd
```

**Using OpenSSL:**
```bash
# Generate private key
openssl genrsa -out client.key 2048

# Generate certificate
openssl req -new -x509 -key client.key -out client.crt -days 365 -subj "/CN=TestClient"

# Convert to PKCS#12 format
openssl pkcs12 -export -out client.pfx -inkey client.key -in client.crt -password pass:password123
```

## Example Usage

### Test Public Endpoint (No Certificate Required)
```bash
curl -k https://localhost:5001/Public/info
```

**Expected Output:**
```json
{
  "message": "This is public data - no certificate required",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Test Secure Endpoint (Certificate Required)
```bash
curl -k --cert client.pfx:password123 https://localhost:5001/Secure/data
```

**Expected Output:**
```json
{
  "message": "This is protected data accessed via certificate authentication",
  "subject": "CN=TestClient",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Test Without Certificate (Should Fail)
```bash
curl -k https://localhost:5001/Secure/data
```

**Expected Output:**
```
401 Unauthorized
```

## Key Features

- **X.509 Certificate Authentication**: Validates client certificates
- **Claims-based Identity**: Extracts user information from certificate subject
- **Flexible Configuration**: Supports various certificate validation options
- **Development-friendly**: Disabled revocation checking for testing

## Security Notes

- In production, enable certificate revocation checking
- Use certificates from trusted Certificate Authorities
- Implement proper certificate validation logic
- Consider certificate renewal strategies