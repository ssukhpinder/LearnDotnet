# Passwordless Authentication Sample

This sample demonstrates how to implement passwordless authentication in ASP.NET Core using magic links sent via email.

## Purpose

Passwordless authentication eliminates the need for users to remember passwords by sending them a secure, time-limited link via email. When clicked, this "magic link" authenticates the user automatically.

## Features

- **Magic Link Generation**: Creates secure JWT tokens for authentication
- **Email Integration**: Sends magic links via email (simulated in console for demo)
- **User Management**: Automatically creates users on first login attempt
- **Security**: Time-limited tokens (15 minutes expiration)
- **Clean UI**: Bootstrap-based responsive interface

## Setup Instructions

### Prerequisites
- .NET 8.0 SDK
- Visual Studio 2022 or VS Code

### Build and Run

1. **Navigate to the project directory:**
   ```bash
   cd samples/passwordless-authentication/PasswordlessAuthSample
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
   ```
   https://localhost:5001
   ```

## Example Usage

### Step 1: Request Magic Link
1. Click "Login with Magic Link" on the home page
2. Enter your email address
3. Click "Send Magic Link"

### Step 2: Check Console Output
Since this is a demo, the magic link will be displayed in the console output:
```
Magic link for user@example.com: https://localhost:5001/Account/VerifyMagicLink?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Step 3: Authenticate
1. Copy the magic link from the console
2. Paste it into your browser
3. You'll be automatically logged in and redirected to the home page

### Expected Output
- **Before Authentication**: Shows "Not authenticated" message with login button
- **After Authentication**: Shows welcome message with user email and logout option
- **Console**: Displays the magic link for testing purposes

## How It Works

1. **User Registration**: Users are automatically created when they first request a magic link
2. **Token Generation**: JWT tokens are created with the user's email and 15-minute expiration
3. **Email Simulation**: In production, you'd integrate with an email service (SendGrid, AWS SES, etc.)
4. **Token Validation**: Magic links are validated for authenticity and expiration
5. **Authentication**: Valid tokens automatically sign in the user

## Security Considerations

- Tokens expire after 15 minutes
- JWT tokens are signed with a secret key
- Users are automatically created but can be extended with additional validation
- In production, use HTTPS and secure email delivery

## Production Deployment

For production use:
1. Replace the console email service with a real email provider
2. Use a secure, randomly generated secret key
3. Store the secret key in configuration (Azure Key Vault, AWS Secrets Manager)
4. Implement rate limiting for magic link requests
5. Add user verification and additional security measures