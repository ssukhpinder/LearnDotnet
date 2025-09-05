namespace PasswordlessAuthSample.Services;

public interface IEmailService
{
    Task SendMagicLinkAsync(string email, string magicLink);
}