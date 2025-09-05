# Biometric Authentication Sample

This sample demonstrates how to implement biometric authentication in ASP.NET Core using simulated WebAuthn/FIDO2 concepts.

## Purpose

This sample shows:
- User registration with biometric enrollment
- Biometric authentication flow
- Fallback to password authentication
- Secure credential storage and verification
- Simulated fingerprint authentication

## Features

- 🔐 **Biometric Registration**: Enroll biometric credentials during account setup
- 👆 **Fingerprint Simulation**: Simulated biometric authentication process
- 🔒 **Secure Authentication**: Challenge-response authentication pattern
- ⚡ **Fast Login**: Quick authentication without passwords
- 🔄 **Fallback Support**: Password authentication as backup

## Setup Instructions

### Prerequisites
- .NET 8.0 SDK
- Visual Studio 2022 or VS Code

### Build and Run

1. **Navigate to the project directory:**
   ```bash
   cd samples/biometric-authentication/BiometricAuthSample
   ```

2. **Restore dependencies:**
   ```bash
   dotnet restore
   ```

3. **Run the application:**
   ```bash
   dotnet run
   ```

4. **Open your browser and navigate to:**
   - HTTP: `http://localhost:5000`
   - HTTPS: `https://localhost:7000`

## Usage Example

### 1. Register a New Account
1. Click "Register" on the home page
2. Enter email and password
3. After registration, you'll be redirected to biometric setup

### 2. Setup Biometric Authentication
1. Click "Enable Biometric Authentication"
2. The system simulates fingerprint enrollment
3. Your biometric credential is stored securely

### 3. Login with Biometrics
1. Enter your email on the login page
2. If biometrics are enabled, you'll be redirected to biometric login
3. Click "Authenticate" to simulate fingerprint scanning
4. You'll be logged in automatically upon successful authentication

### Expected Output

**Registration Flow:**
```
1. User registers → Account created
2. Redirected to biometric setup → Credential enrolled
3. Biometric authentication enabled → Ready to use
```

**Login Flow:**
```
1. User enters email → System detects biometric capability
2. Redirected to biometric login → Challenge generated
3. Biometric authentication → Signature verified
4. User logged in → Access granted
```

## Technical Implementation

### Key Components

- **BiometricService**: Handles credential management and verification
- **ApplicationUser**: Extended with biometric properties
- **Challenge-Response**: Secure authentication pattern
- **Simulated WebAuthn**: Demonstrates real-world concepts

### Security Features

- **Challenge Generation**: Random challenges prevent replay attacks
- **Signature Verification**: Cryptographic signature validation
- **Credential Storage**: Secure storage of biometric credentials
- **Fallback Authentication**: Password backup when biometrics fail

## Important Notes

⚠️ **This is a simulation** - Real biometric authentication requires:
- WebAuthn/FIDO2 implementation
- Hardware security modules
- Actual biometric sensors
- Browser WebAuthn API integration

The sample demonstrates the authentication flow and security concepts that would be used in a production biometric authentication system.

## Next Steps

To implement real biometric authentication:
1. Integrate WebAuthn/FIDO2 libraries
2. Use hardware security keys or platform authenticators
3. Implement proper cryptographic verification
4. Add device management and recovery options