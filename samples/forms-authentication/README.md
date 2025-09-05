# Forms Authentication Sample

## Purpose

This sample demonstrates how to implement forms-based authentication in ASP.NET Core using cookies. It shows the complete authentication flow including login, logout, and protecting routes with the `[Authorize]` attribute.

## Key Features

- Cookie-based authentication
- Login/logout functionality
- Protected routes
- User claims and roles
- Access denied handling
- Simple HTML forms for authentication

## Setup Instructions

### Prerequisites
- .NET 8.0 SDK or later
- Any code editor (Visual Studio, VS Code, etc.)

### Build and Run

1. Navigate to the project directory:
   ```bash
   cd samples/forms-authentication/FormsAuthSample
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

5. Open your browser and navigate to `https://localhost:5001` (or the URL shown in the console)

## Example Usage

### Demo Credentials
- **Username:** admin
- **Password:** password

### Testing the Authentication Flow

1. **Visit the Home Page** - Accessible without authentication
2. **Try the Secure Page** - Click "Secure Page" link, you'll be redirected to login
3. **Login** - Use the demo credentials above
4. **Access Protected Content** - After login, you can access the secure page
5. **Logout** - Click "Logout" to end the session

### Expected Output

**Before Login:**
- Home page shows "You are not logged in"
- Accessing secure page redirects to login

**After Login:**
- Home page displays user information
- Secure page shows protected content with user details
- Navigation shows "Welcome, admin!" and logout option

## Code Structure

- `Program.cs` - Authentication configuration
- `Controllers/AccountController.cs` - Login/logout logic
- `Controllers/HomeController.cs` - Public and protected pages
- `Views/` - HTML templates for the UI

## Key Concepts Demonstrated

- **Cookie Authentication Setup** - Configuring authentication middleware
- **Claims-based Identity** - Creating user claims and roles
- **Route Protection** - Using `[Authorize]` attribute
- **Authentication State** - Checking if user is authenticated
- **Sign In/Out Process** - Managing authentication cookies