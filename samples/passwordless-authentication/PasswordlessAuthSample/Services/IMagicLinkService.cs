namespace PasswordlessAuthSample.Services;

public interface IMagicLinkService
{
    string GenerateMagicLink(string email);
    bool ValidateMagicLink(string token, out string email);
}