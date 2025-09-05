# JWT Authentication Sample

This sample demonstrates how to implement JWT (JSON Web Token) authentication in ASP.NET Core.

## Purpose

JWT authentication is a stateless authentication mechanism where the server generates a signed token containing user claims. The client includes this token in subsequent requests to access protected resources.

## Setup Instructions

### Prerequisites
- .NET 9.0 SDK or later
- Visual Studio 2022 or VS Code

### Build and Run

1. Navigate to the project directory:
   ```bash
   cd samples/jwt-authentication/JwtAuthSample
   ```

2. Restore dependencies:
   ```bash
   dotnet restore
   ```

3. Run the application:
   ```bash
   dotnet run
   ```

The API will be available at `https://localhost:5001` (or the port shown in the console).

## Example Usage

### 1. Login to Get JWT Token

**Request:**
```bash
POST https://localhost:5001/Auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

**Expected Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 2. Access Protected Resource

**Request:**
```bash
GET https://localhost:5001/Secure/data
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Expected Response:**
```json
{
  "message": "This is protected data",
  "user": "admin",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### 3. Access Without Token (Should Fail)

**Request:**
```bash
GET https://localhost:5001/Secure/data
```

**Expected Response:**
```
401 Unauthorized
```

## Key Components

- **JWT Configuration**: Configured in `Program.cs` with symmetric key validation
- **AuthController**: Handles login and JWT token generation
- **SecureController**: Protected endpoints requiring valid JWT tokens
- **Token Validation**: Automatic validation of JWT tokens on protected routes

## Security Notes

- In production, use a secure, randomly generated secret key
- Store the secret key in configuration (appsettings.json, environment variables, or Azure Key Vault)
- Consider token expiration and refresh token mechanisms
- Use HTTPS in production environments