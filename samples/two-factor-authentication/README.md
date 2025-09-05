# Two-Factor Authentication (2FA/MFA) Sample

This sample demonstrates how to implement Two-Factor Authentication (2FA) using ASP.NET Core Identity and Time-based One-Time Passwords (TOTP).

## Purpose

This sample shows:
- User registration and login with ASP.NET Core Identity
- Setting up 2FA with authenticator apps (Google Authenticator, Microsoft Authenticator, etc.)
- QR code generation for easy setup
- TOTP verification during login
- Secure authentication flow with multiple factors

## Prerequisites

- .NET 8.0 SDK
- An authenticator app on your mobile device (Google Authenticator, Microsoft Authenticator, Authy, etc.)

## Setup Instructions

### 1. Build and Run

```bash
cd samples/two-factor-authentication/TwoFactorAuthSample
dotnet restore
dotnet run
```

The application will start at `https://localhost:5001` or `http://localhost:5000`.

### 2. Test the Application

1. **Register a new account:**
   - Navigate to `/Account/Register`
   - Enter email and password
   - You'll be automatically redirected to 2FA setup

2. **Setup Two-Factor Authentication:**
   - Scan the QR code with your authenticator app
   - Or manually enter the provided key
   - Enter the 6-digit code from your app to enable 2FA

3. **Test Login with 2FA:**
   - Logout and login again
   - Enter your email/password
   - You'll be prompted for the 2FA code
   - Enter the current code from your authenticator app

## Example Usage

### Registration Flow
```
1. User registers → /Account/Register
2. Automatic login → Redirect to /Account/Setup2FA
3. Scan QR code with authenticator app
4. Enter verification code → 2FA enabled
```

### Login Flow
```
1. User enters credentials → /Account/Login
2. If 2FA enabled → Redirect to /Account/Verify2FA
3. Enter TOTP code from authenticator app
4. Successful login → Access protected resources
```

## Expected Output

- **Home Page**: Shows authentication status
- **Registration**: Creates account and redirects to 2FA setup
- **2FA Setup**: Displays QR code and manual key for authenticator app configuration
- **Login**: Standard login form, redirects to 2FA verification if enabled
- **2FA Verification**: Prompts for 6-digit TOTP code from authenticator app

## Key Features

- **TOTP (Time-based One-Time Password)**: Uses RFC 6238 standard
- **QR Code Generation**: Easy setup with authenticator apps
- **In-Memory Database**: No external database required for demo
- **ASP.NET Core Identity**: Built-in user management and authentication
- **Secure Token Generation**: Cryptographically secure random keys

## Security Notes

- Uses ASP.NET Core Identity's built-in 2FA support
- TOTP keys are securely generated and stored
- Codes expire every 30 seconds (standard TOTP interval)
- In production, use a persistent database instead of in-memory storage