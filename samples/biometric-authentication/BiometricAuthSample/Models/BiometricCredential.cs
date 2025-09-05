namespace BiometricAuthSample.Models;

public class BiometricCredential
{
    public string Id { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public string UserId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}