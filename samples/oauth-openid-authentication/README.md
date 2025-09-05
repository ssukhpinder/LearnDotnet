# OAuth 2.0 / OpenID Connect Authentication Sample

## Purpose

This sample demonstrates how to implement OAuth 2.0 and OpenID Connect authentication in ASP.NET Core. It shows how to:

- Configure OpenID Connect authentication with an external provider
- Handle the OAuth 2.0 authorization code flow
- Protect API endpoints with authentication
- Access user claims and profile information

## Setup Instructions

### Prerequisites
- .NET 8.0 SDK or later
- Visual Studio 2022 or VS Code

### Build and Run

1. Navigate to the project directory:
   ```bash
   cd samples/oauth-openid-authentication/OAuthOpenIdSample
   ```

2. Restore dependencies:
   ```bash
   dotnet restore
   ```

3. Run the application:
   ```bash
   dotnet run
   ```

4. The application will start on `https://localhost:5001` (or the port shown in the console)

## Example Usage

### 1. Start Authentication Flow
Navigate to: `https://localhost:5001/auth/login`

This will redirect you to the Duende IdentityServer demo for authentication.

### 2. Complete Authentication
- Use the demo credentials or create a test account
- After successful authentication, you'll be redirected back to `/auth/callback`

### 3. Access Protected Resources
Once authenticated, you can access:
- `https://localhost:5001/secure/profile` - Returns user profile information

### 4. Logout
Navigate to: `https://localhost:5001/auth/logout`

## Expected Output

### Authentication Callback Response:
```json
{
  "message": "Authentication successful",
  "user": "alice",
  "claims": [
    {
      "type": "sub",
      "value": "818727"
    },
    {
      "type": "name",
      "value": "Alice Smith"
    },
    {
      "type": "email",
      "value": "alice@example.com"
    }
  ]
}
```

### Protected Profile Response:
```json
{
  "message": "This is protected user profile data",
  "user": "alice",
  "claims": [...],
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Configuration Notes

- Uses Duende IdentityServer demo as the OpenID Connect provider
- Implements Authorization Code flow with PKCE
- Stores tokens in cookies for session management
- Requests `openid`, `profile`, and `email` scopes

## Security Considerations

- In production, use your own identity provider
- Configure proper redirect URIs
- Use HTTPS for all communications
- Implement proper token validation and refresh logic