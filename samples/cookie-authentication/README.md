# Cookie-Based Authentication Sample

## Purpose

This sample demonstrates how to implement cookie-based authentication in ASP.NET Core Web API. It shows how to:
- Configure cookie authentication middleware
- Create login/logout endpoints
- Protect API endpoints with authentication
- Handle user claims and roles

## Setup Instructions

### Prerequisites
- .NET 8.0 SDK or later

### Build and Run
1. Navigate to the project directory:
   ```bash
   cd samples/cookie-authentication/CookieAuthSample
   ```

2. Restore dependencies:
   ```bash
   dotnet restore
   ```

3. Run the application:
   ```bash
   dotnet run
   ```

The API will be available at `http://localhost:5000`

## Example Usage

### 1. Login
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}' \
  -c cookies.txt
```

**Expected Output:**
```json
{"message": "Login successful"}
```

### 2. Access Protected Endpoint
```bash
curl -X GET http://localhost:5000/secure/data \
  -b cookies.txt
```

**Expected Output:**
```json
{
  "message": "This is protected data",
  "user": "admin",
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

### 3. Get User Profile
```bash
curl -X GET http://localhost:5000/auth/profile \
  -b cookies.txt
```

**Expected Output:**
```json
{
  "username": "admin",
  "role": "Admin"
}
```

### 4. Logout
```bash
curl -X POST http://localhost:5000/auth/logout \
  -b cookies.txt
```

**Expected Output:**
```json
{"message": "Logout successful"}
```

## Key Features

- **Secure Cookie Storage**: Authentication state stored in HTTP-only cookies
- **Automatic Expiration**: Cookies expire after 30 minutes of inactivity
- **Claims-Based Identity**: User information stored as claims
- **Protected Routes**: Endpoints require authentication via `[Authorize]` attribute

## Test Credentials
- Username: `admin`
- Password: `password`