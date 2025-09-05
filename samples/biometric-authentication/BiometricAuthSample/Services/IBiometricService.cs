using BiometricAuthSample.Models;

namespace BiometricAuthSample.Services;

public interface IBiometricService
{
    Task<string> GenerateChallenge();
    Task<bool> VerifyBiometric(string credentialId, string signature, string challenge);
    Task<BiometricCredential> RegisterBiometric(string userId, string publicKey);
}