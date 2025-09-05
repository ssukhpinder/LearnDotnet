namespace PasswordlessAuthSample.Services;

public class EmailService : IEmailService
{
    private readonly ILogger<EmailService> _logger;

    public EmailService(ILogger<EmailService> logger)
    {
        _logger = logger;
    }

    public Task SendMagicLinkAsync(string email, string magicLink)
    {
        // In a real application, you would send an actual email
        // For demo purposes, we'll just log the magic link
        _logger.LogInformation("Magic link for {Email}: {MagicLink}", email, magicLink);
        Console.WriteLine($"Magic link for {email}: {magicLink}");
        return Task.CompletedTask;
    }
}