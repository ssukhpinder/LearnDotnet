# API Key Authentication Sample

## Purpose

This sample demonstrates how to implement API key authentication in ASP.NET Core using custom middleware. API keys are a simple authentication method where clients include a secret key in their requests to access protected resources.

## Setup Instructions

### Prerequisites
- .NET 8.0 SDK or later

### Build and Run

1. Navigate to the project directory:
   ```bash
   cd samples/api-key-authentication/ApiKeyAuthSample
   ```

2. Build the project:
   ```bash
   dotnet build
   ```

3. Run the application:
   ```bash
   dotnet run
   ```

The application will start on `https://localhost:5001` (or the port shown in the console).

## Example Usage

### Valid Request (with API Key)
```bash
curl -H "X-API-Key: my-secret-api-key-123" https://localhost:5001/secure/data
```

**Expected Output:**
```json
{
  "message": "This is protected data accessed with API key",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### Invalid Request (without API Key)
```bash
curl https://localhost:5001/secure/data
```

**Expected Output:**
```
API Key missing
```
Status Code: 401 Unauthorized

### Invalid Request (wrong API Key)
```bash
curl -H "X-API-Key: wrong-key" https://localhost:5001/secure/data
```

**Expected Output:**
```
Invalid API Key
```
Status Code: 401 Unauthorized

## How It Works

1. **Middleware**: The `ApiKeyMiddleware` intercepts all requests and checks for the `X-API-Key` header
2. **Validation**: Compares the provided key against the expected value
3. **Authorization**: Only allows requests with valid API keys to proceed to controllers
4. **Response**: Returns 401 Unauthorized for missing or invalid keys

## Security Notes

- In production, store API keys securely (environment variables, Azure Key Vault, etc.)
- Consider using HTTPS to protect API keys in transit
- Implement rate limiting and logging for security monitoring