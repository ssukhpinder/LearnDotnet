using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace CertificatePinningAuthSample.Services;

public class CertificatePinningService
{
    private readonly HashSet<string> _pinnedCertificates;
    private readonly ILogger<CertificatePinningService> _logger;

    public CertificatePinningService(ILogger<CertificatePinningService> logger)
    {
        _logger = logger;
        _pinnedCertificates = new HashSet<string>
        {
            // Example pinned certificate thumbprints (SHA-1)
            "B13EC36903F8BF4701D498261A0802EF63642BC3", // Example: GitHub.com
            "5FB7EE0633E259DBAD0C4C9AE6D38F1A61C7DC25"  // Example: Google.com
        };
    }

    public bool ValidateCertificate(X509Certificate2 certificate)
    {
        var thumbprint = certificate.Thumbprint;
        var isValid = _pinnedCertificates.Contains(thumbprint);
        
        _logger.LogInformation("Certificate validation: {Thumbprint} - {Result}", 
            thumbprint, isValid ? "VALID" : "INVALID");
        
        return isValid;
    }

    public bool ValidateServerCertificate(object sender, X509Certificate? certificate, 
        X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        if (certificate == null) return false;
        
        var cert2 = new X509Certificate2(certificate);
        return ValidateCertificate(cert2);
    }

    public string GetCertificateFingerprint(X509Certificate2 certificate)
    {
        return certificate.Thumbprint;
    }

    public void AddPinnedCertificate(string thumbprint)
    {
        _pinnedCertificates.Add(thumbprint.ToUpperInvariant());
        _logger.LogInformation("Added pinned certificate: {Thumbprint}", thumbprint);
    }
}