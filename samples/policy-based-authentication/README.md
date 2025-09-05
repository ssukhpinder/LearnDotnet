# Policy-Based Authentication Sample

## Purpose

This sample demonstrates how to implement Policy-Based Authentication in ASP.NET Core. Policy-based authentication allows you to create complex authorization rules using custom requirements and handlers, providing fine-grained control over access to your application's resources.

## Key Concepts Demonstrated

- **Custom Authorization Requirements**: Define specific business rules
- **Authorization Handlers**: Implement the logic for evaluating requirements
- **Policy Configuration**: Combine requirements into reusable policies
- **Resource-Based Authorization**: Protect resources based on ownership
- **Programmatic Authorization**: Check policies in code

## Setup Instructions

### Prerequisites
- .NET 8.0 SDK or later
- Visual Studio 2022 or VS Code

### Build and Run

1. Navigate to the project directory:
   ```bash
   cd samples/policy-based-authentication/PolicyAuthSample
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

### 1. Login with Different User Types
```bash
# Young user (under 18)
curl -X POST "https://localhost:7000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=teen&role=user&age=16&department=IT"

# Adult user
curl -X POST "https://localhost:7000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&role=user&age=25&department=IT"

# Senior employee
curl -X POST "https://localhost:7000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=manager&role=manager&age=35&department=Management"

# Finance manager
curl -X POST "https://localhost:7000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=finmgr&role=manager&age=40&department=Finance"
```

### 2. Test Policy-Protected Endpoints
```bash
# Test adult-only content (requires age >= 18)
curl -X GET "https://localhost:7000/adult-content" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"

# Test senior employee area (requires age >= 25 AND Management/HR department)
curl -X GET "https://localhost:7000/senior-employee" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"

# Test finance access (requires manager/admin role, Finance/Accounting dept, business hours)
curl -X GET "https://localhost:7000/finance" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"
```

### 3. Test Resource-Based Authorization
```bash
# Get all documents
curl -X GET "https://localhost:7000/documents" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"

# Access document owned by current user
curl -X GET "https://localhost:7000/documents/1" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"
```

### 4. Programmatic Policy Checking
```bash
# Check specific policy
curl -X GET "https://localhost:7000/api/policy/check-policy/Adult" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"

# Check custom requirement
curl -X GET "https://localhost:7000/api/policy/check-requirement?minimumAge=21" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"

# Check department requirement
curl -X GET "https://localhost:7000/api/policy/department-check?departments=IT&departments=Finance" \
  -H "Cookie: .AspNetCore.Cookies=<cookie-value>"
```

### Expected Outputs

**Login Response:**
```json
{
  "message": "Logged in successfully",
  "claims": [
    { "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", "value": "john" },
    { "type": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "value": "john" },
    { "type": "role", "value": "user" },
    { "type": "age", "value": "25" },
    { "type": "department", "value": "IT" }
  ]
}
```

**Policy Check Response:**
```json
{
  "policy": "Adult",
  "authorized": true
}
```

**Business Hours Check:**
```json
{
  "currentTime": "14:30:00",
  "businessHours": "09:00 - 17:00",
  "authorized": true
}
```

## Available Endpoints

| Endpoint | Method | Policy | Description |
|----------|--------|--------|-------------|
| `/login` | POST | None | Login with user attributes |
| `/logout` | POST | None | Logout current user |
| `/adult-content` | GET | Adult | Requires age >= 18 |
| `/senior-employee` | GET | SeniorEmployee | Requires age >= 25 AND Management/HR dept |
| `/finance` | GET | FinanceAccess | Complex policy with multiple requirements |
| `/documents` | GET | Authenticated | List all documents |
| `/documents/{id}` | GET | ResourceOwner | Access document if owned by user |
| `/api/policy/check-policy/{name}` | GET | Authenticated | Check specific policy |
| `/api/policy/check-requirement` | GET | Authenticated | Test custom requirement |
| `/api/policy/department-check` | GET | Authenticated | Test department requirement |
| `/api/policy/business-hours` | GET | Authenticated | Test business hours requirement |

## Authorization Policies

### Adult Policy
- **Requirement**: MinimumAgeRequirement(18)
- **Logic**: User must have age claim >= 18

### SeniorEmployee Policy
- **Requirements**: 
  - MinimumAgeRequirement(25)
  - DepartmentRequirement("Management", "HR")
- **Logic**: User must be 25+ AND in Management or HR department

### FinanceAccess Policy
- **Requirements**:
  - RequireClaim("role", "manager", "admin")
  - DepartmentRequirement("Finance", "Accounting")
  - BusinessHoursRequirement(09:00, 17:00)
- **Logic**: User must be manager/admin AND in Finance/Accounting AND during business hours

### ResourceOwner Policy
- **Requirement**: ResourceOwnerRequirement
- **Logic**: User must own the requested resource

## Testing Scenarios

### Scenario 1: Age-Based Access
1. Login as teen (age 16): `username=teen&age=16`
2. Try accessing `/adult-content` → Should be denied
3. Login as adult (age 25): `username=adult&age=25`
4. Try accessing `/adult-content` → Should be allowed

### Scenario 2: Department-Based Access
1. Login as IT user: `username=it&department=IT`
2. Try accessing `/senior-employee` → Should be denied (wrong department)
3. Login as HR manager: `username=hr&department=HR&age=30`
4. Try accessing `/senior-employee` → Should be allowed

### Scenario 3: Time-Based Access
1. Login as finance manager during business hours
2. Try accessing `/finance` → Should be allowed
3. Try the same outside business hours → Should be denied

### Scenario 4: Resource Ownership
1. Login as user1: `username=user1`
2. Try accessing `/documents/1` (owned by user1) → Should be allowed
3. Try accessing `/documents/3` (owned by admin) → Should be denied

## Custom Requirements

The sample includes several custom authorization requirements:

- **MinimumAgeRequirement**: Checks if user meets minimum age
- **DepartmentRequirement**: Validates user's department
- **ResourceOwnerRequirement**: Ensures user owns the resource
- **BusinessHoursRequirement**: Restricts access to business hours

Each requirement has a corresponding handler that implements the authorization logic.