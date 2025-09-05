# Claims-Based Authentication Sample

## Purpose

This sample demonstrates how to implement Claims-Based Authentication in ASP.NET Core. Claims-based authentication allows you to make authorization decisions based on user attributes (claims) rather than just roles, providing more granular and flexible access control.

## Key Concepts Demonstrated

- **Claims Identity**: Creating user identities with custom claims
- **Authorization Policies**: Defining policies based on claims
- **Claim-based Authorization**: Protecting endpoints with claim requirements
- **Custom Authorization Logic**: Using assertion-based policies

## Setup Instructions

### Prerequisites
- .NET 8.0 SDK or later
- Visual Studio 2022 or VS Code

### Build and Run

1. Navigate to the project directory:
   ```bash
   cd samples/claims-based-authentication/ClaimsAuthSample
   ```

2. Restore dependencies:
   ```bash
   dotnet restore
   ```

3. Build the project:
   ```bash
   dotnet build
   ```

4. Run the application:
   ```bash
   dotnet run
   ```

5. Open your browser and navigate to `https://localhost:7000/swagger` (or the URL shown in the console)

## Example Usage

### 1. Login with Claims
```bash
# Login as regular user
curl -X POST "https://localhost:7000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&role=user&age=25&department=IT"

# Login as admin
curl -X POST "https://localhost:7000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&role=admin&age=30&department=Management"
```

### 2. Access Protected Endpoints
```bash
# Get user profile (requires authentication)
curl -X GET "https://localhost:7000/profile" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"

# Access admin-only endpoint
curl -X GET "https://localhost:7000/admin" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"

# Check specific claims
curl -X GET "https://localhost:7000/api/claims/check-claim/role/admin" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"
```

### 3. Expected Outputs

**Login Response:**
```json
{
  "message": "Logged in successfully",
  "claims": [
    { "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "value": "john" },
    { "type": "role", "value": "user" },
    { "type": "age", "value": "25" },
    { "type": "department", "value": "IT" }
  ]
}
```

**Profile Response:**
```json
{
  "username": "john",
  "claims": [
    { "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "value": "john" },
    { "type": "role", "value": "user" },
    { "type": "age", "value": "25" },
    { "type": "department", "value": "IT" }
  ]
}
```

## Available Endpoints

| Endpoint | Method | Authorization | Description |
|----------|--------|---------------|-------------|
| `/login` | POST | None | Login with username and claims |
| `/logout` | POST | None | Logout current user |
| `/profile` | GET | Authenticated | Get current user profile |
| `/admin` | GET | AdminOnly policy | Admin-only access |
| `/manager` | GET | ManagerOrAdmin policy | Manager or Admin access |
| `/adult-only` | GET | MinimumAge policy | Age >= 18 required |
| `/api/claims/my-claims` | GET | Authenticated | Get all user claims |
| `/api/claims/check-claim/{type}/{value}` | GET | Authenticated | Check specific claim |
| `/api/claims/department-data` | GET | DepartmentAccess policy | Department-specific data |

## Authorization Policies

- **AdminOnly**: Requires `role` claim with value `admin`
- **ManagerOrAdmin**: Requires `role` claim with value `manager` or `admin`
- **MinimumAge**: Requires `age` claim with value >= 18
- **DepartmentAccess**: Requires any `department` claim

## Testing Different Scenarios

1. **Regular User**: `username=john&role=user&age=25&department=IT`
2. **Manager**: `username=jane&role=manager&age=35&department=Sales`
3. **Admin**: `username=admin&role=admin&age=40&department=Management`
4. **Minor User**: `username=teen&role=user&age=16&department=Intern`

Try accessing different endpoints with these user types to see how claims-based authorization works.