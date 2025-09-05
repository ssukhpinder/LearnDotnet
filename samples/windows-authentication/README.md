# Windows Authentication Sample

## Purpose

This sample demonstrates how to implement Windows Authentication in ASP.NET Core applications. Windows Authentication uses the current Windows user's credentials to authenticate requests, making it ideal for intranet applications where users are already logged into a Windows domain.

## Setup Instructions

### Prerequisites
- .NET 8.0 SDK
- Windows operating system
- IIS Express or IIS (for production scenarios)

### Build and Run

1. Navigate to the project directory:
   ```bash
   cd samples/windows-authentication/WindowsAuthSample
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

The application will start on `http://localhost:5000`

## Example Usage

### Test the Authentication

1. Open your browser and navigate to: `http://localhost:5000/secure/user-info`

2. You should see a JSON response with your Windows user information:
   ```json
   {
     "username": "DOMAIN\\username",
     "authenticationType": "Negotiate",
     "isAuthenticated": true,
     "groups": ["DOMAIN\\Domain Users", "BUILTIN\\Users"],
     "timestamp": "2024-01-15T10:30:00.000Z"
   }
   ```

### Expected Output

- **username**: Your Windows domain and username
- **authenticationType**: "Negotiate" (Kerberos/NTLM)
- **isAuthenticated**: true if authentication succeeded
- **groups**: Windows groups you belong to
- **timestamp**: Current UTC timestamp

## Key Features

- Automatic Windows user authentication
- Access to Windows user groups
- No login form required
- Seamless integration with Windows domain

## Notes

- Windows Authentication works best in intranet scenarios
- Requires proper IIS configuration for production
- May prompt for credentials in some browsers if not on domain