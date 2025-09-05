# LearnDotnet Authentication Samples

This repository contains a collection of authentication and authorization samples built with ASP.NET Core (.NET 8/9). Each sample demonstrates a different authentication technique or security scenario. These projects are intended for learning and demonstration purposes.

## Projects Overview

### 1. LearnDotnet
A basic .NET console project. Used for simple C# code demonstrations.

### 2. FormsAuthSample
Demonstrates classic forms authentication using cookies in ASP.NET Core MVC. Includes login, logout, and secure pages.

### 3. CertificatePinningAuthSample
Shows how to implement certificate pinning for outgoing HTTP requests to enhance security against man-in-the-middle attacks.

### 4. PasswordlessAuthSample
Implements passwordless authentication using magic links sent via email. Built with ASP.NET Core Identity and in-memory database.

### 5. ApiKeyAuthSample
Demonstrates API key authentication for securing APIs. Clients must provide a valid API key in requests.

### 6. OAuthOpenIdSample
Shows how to integrate OAuth 2.0 and OpenID Connect authentication using an external identity provider.

### 7. TwoFactorAuthSample
Implements two-factor authentication (2FA) using ASP.NET Core Identity. Users must complete a second verification step after login.

### 8. JwtAuthSample
Demonstrates stateless authentication using JSON Web Tokens (JWT). Includes token generation and validation for API endpoints.

### 9. CookieAuthSample
Shows cookie-based authentication for APIs. Includes login, logout, and profile endpoints protected by cookies.

### 10. PolicyAuthSample
Demonstrates policy-based authorization with custom requirements and handlers. Includes sample policies for age, department, and resource ownership.

### 11. BiometricAuthSample
Simulates biometric authentication (e.g., fingerprint) using WebAuthn/FIDO2 concepts. Built with ASP.NET Core Identity.

### 12. WindowsAuthSample
Demonstrates Windows Authentication for intranet scenarios. Secures endpoints using the current Windows user context.

### 13. CertificateAuthSample
Shows how to secure APIs using client certificate authentication. Includes public and protected endpoints.

---

## Getting Started

Each sample is a standalone ASP.NET Core project. To run a sample:
1. Open the solution in Visual Studio or VS Code.
2. Set the desired project as the startup project.
3. Build and run the project.
4. Follow the instructions in the browser or API documentation (Swagger where available).

## Requirements
- .NET 8.0 or .NET 9.0 SDK
- Visual Studio 2022+ or VS Code

## License
This repository is for educational purposes.

