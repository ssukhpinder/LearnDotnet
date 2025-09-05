using BiometricAuthSample.Data;
using BiometricAuthSample.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

namespace BiometricAuthSample.Services;

public class BiometricService : IBiometricService
{
    private readonly ApplicationDbContext _context;

    public BiometricService(ApplicationDbContext context)
    {
        _context = context;
    }

    public Task<string> GenerateChallenge()
    {
        var challenge = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        return Task.FromResult(challenge);
    }

    public async Task<bool> VerifyBiometric(string credentialId, string signature, string challenge)
    {
        var credential = await _context.BiometricCredentials
            .FirstOrDefaultAsync(c => c.Id == credentialId);

        if (credential == null) return false;

        // Simulate biometric verification (in real implementation, this would verify the signature)
        var expectedSignature = Convert.ToBase64String(
            SHA256.HashData(Encoding.UTF8.GetBytes(challenge + credential.PublicKey)));
        
        return signature == expectedSignature;
    }

    public async Task<BiometricCredential> RegisterBiometric(string userId, string publicKey)
    {
        var credential = new BiometricCredential
        {
            Id = Guid.NewGuid().ToString(),
            UserId = userId,
            PublicKey = publicKey
        };

        _context.BiometricCredentials.Add(credential);
        await _context.SaveChangesAsync();
        return credential;
    }
}