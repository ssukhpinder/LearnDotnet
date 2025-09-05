# Complete Guide to Certificate Pinning Authentication in .NET

## Table of Contents

1. [Introduction](#introduction)
2. [Understanding Certificate Pinning](#understanding-certificate-pinning)
3. [Types of Certificate Pinning](#types-of-certificate-pinning)
4. [Implementation in .NET](#implementation-in-net)
5. [Security Considerations](#security-considerations)
6. [Best Practices](#best-practices)
7. [Common Pitfalls](#common-pitfalls)
8. [Advanced Scenarios](#advanced-scenarios)
9. [Testing and Validation](#testing-and-validation)
10. [Production Deployment](#production-deployment)

## Introduction

Certificate Pinning, also known as SSL/TLS Pinning or Public Key Pinning, is a critical security technique used to prevent man-in-the-middle (MITM) attacks by validating that a server's certificate matches a pre-configured trusted certificate or public key. This guide provides comprehensive coverage of implementing certificate pinning in .NET applications.

### Why Certificate Pinning Matters

In traditional SSL/TLS validation, applications trust any certificate signed by a recognized Certificate Authority (CA). However, this approach has vulnerabilities:

- **Compromised CAs**: If a CA is compromised, attackers can issue valid certificates for any domain
- **Rogue Certificates**: Malicious actors might obtain legitimate certificates through social engineering
- **Government Interception**: State actors may compel CAs to issue certificates for surveillance
- **Corporate Proxies**: Corporate firewalls may use their own certificates for traffic inspection

Certificate pinning addresses these vulnerabilities by establishing a direct trust relationship with specific certificates or public keys.

## Understanding Certificate Pinning

### How Certificate Pinning Works

1. **Pin Storage**: The application stores trusted certificate fingerprints or public keys
2. **Connection Attempt**: When connecting to a server, the application receives the server's certificate
3. **Validation**: The application compares the received certificate against its pinned certificates
4. **Decision**: The connection is allowed only if the certificate matches a pinned certificate

### Certificate vs. Public Key Pinning

**Certificate Pinning:**
- Pins the entire certificate
- More restrictive but simpler to implement
- Requires updates when certificates are renewed

**Public Key Pinning:**
- Pins only the public key portion
- Survives certificate renewals if the same key pair is used
- More flexible but slightly more complex

## Types of Certificate Pinning

### 1. Leaf Certificate Pinning

Pins the end-entity certificate (the server's actual certificate).

```csharp
public class LeafCertificatePinning
{
    private readonly HashSet<string> _pinnedThumbprints = new()
    {
        "A1B2C3D4E5F6789012345678901234567890ABCD" // Server's certificate thumbprint
    };

    public bool ValidateCertificate(X509Certificate2 certificate)
    {
        return _pinnedThumbprints.Contains(certificate.Thumbprint);
    }
}
```

**Pros:**
- Highest security level
- Simple implementation

**Cons:**
- Requires frequent updates
- Service disruption if not updated timely

### 2. Intermediate Certificate Pinning

Pins intermediate CA certificates in the chain.

```csharp
public class IntermediateCertificatePinning
{
    private readonly HashSet<string> _pinnedIntermediates = new()
    {
        "B2C3D4E5F6789012345678901234567890ABCDE" // Intermediate CA thumbprint
    };

    public bool ValidateCertificateChain(X509Chain chain)
    {
        return chain.ChainElements
            .Cast<X509ChainElement>()
            .Any(element => _pinnedIntermediates.Contains(element.Certificate.Thumbprint));
    }
}
```

**Pros:**
- Less frequent updates
- Covers multiple domains under same CA

**Cons:**
- Lower security than leaf pinning
- Vulnerable if intermediate CA is compromised

### 3. Root Certificate Pinning

Pins root CA certificates.

```csharp
public class RootCertificatePinning
{
    private readonly HashSet<string> _pinnedRoots = new()
    {
        "C3D4E5F6789012345678901234567890ABCDEF0" // Root CA thumbprint
    };

    public bool ValidateRootCertificate(X509Chain chain)
    {
        var rootCert = chain.ChainElements[^1].Certificate;
        return _pinnedRoots.Contains(rootCert.Thumbprint);
    }
}
```

**Pros:**
- Minimal maintenance
- Broad coverage

**Cons:**
- Lowest security benefit
- Large attack surface

### 4. Public Key Pinning

Pins the public key instead of the entire certificate.

```csharp
public class PublicKeyPinning
{
    private readonly HashSet<string> _pinnedPublicKeys = new();

    public bool ValidatePublicKey(X509Certificate2 certificate)
    {
        var publicKey = Convert.ToBase64String(certificate.GetPublicKey());
        return _pinnedPublicKeys.Contains(publicKey);
    }
}
```

## Implementation in .NET

### Basic Certificate Pinning Service

```csharp
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public class CertificatePinningService
{
    private readonly Dictionary<string, HashSet<string>> _domainPins;
    private readonly ILogger<CertificatePinningService> _logger;

    public CertificatePinningService(ILogger<CertificatePinningService> logger)
    {
        _logger = logger;
        _domainPins = new Dictionary<string, HashSet<string>>
        {
            ["api.example.com"] = new HashSet<string>
            {
                "A1B2C3D4E5F6789012345678901234567890ABCD",
                "B2C3D4E5F6789012345678901234567890ABCDE1" // Backup certificate
            },
            ["secure.example.com"] = new HashSet<string>
            {
                "C3D4E5F6789012345678901234567890ABCDEF2"
            }
        };
    }

    public bool ValidateServerCertificate(
        HttpRequestMessage request,
        X509Certificate2? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (certificate == null)
        {
            _logger.LogWarning("No certificate provided");
            return false;
        }

        var host = request.RequestUri?.Host;
        if (string.IsNullOrEmpty(host))
        {
            _logger.LogWarning("No host specified in request");
            return false;
        }

        if (!_domainPins.TryGetValue(host, out var pinnedCertificates))
        {
            _logger.LogWarning("No pinned certificates for host: {Host}", host);
            return false;
        }

        var thumbprint = certificate.Thumbprint;
        var isValid = pinnedCertificates.Contains(thumbprint);

        _logger.LogInformation(
            "Certificate validation for {Host}: {Thumbprint} - {Result}",
            host, thumbprint, isValid ? "VALID" : "INVALID");

        return isValid;
    }
}
```

### HttpClient Configuration

```csharp
public class SecureHttpClientFactory
{
    private readonly CertificatePinningService _pinningService;

    public SecureHttpClientFactory(CertificatePinningService pinningService)
    {
        _pinningService = pinningService;
    }

    public HttpClient CreateSecureClient()
    {
        var handler = new HttpClientHandler();
        
        handler.ServerCertificateCustomValidationCallback = 
            (request, certificate, chain, sslPolicyErrors) =>
            {
                // First, perform standard SSL validation
                if (sslPolicyErrors != SslPolicyErrors.None && 
                    sslPolicyErrors != SslPolicyErrors.RemoteCertificateNameMismatch)
                {
                    return false;
                }

                // Then, perform certificate pinning validation
                return _pinningService.ValidateServerCertificate(
                    request, certificate, chain, sslPolicyErrors);
            };

        return new HttpClient(handler);
    }
}
```

### Advanced Pinning with Backup Certificates

```csharp
public class AdvancedCertificatePinning
{
    private readonly Dictionary<string, CertificatePin> _pins;

    public class CertificatePin
    {
        public HashSet<string> Primary { get; set; } = new();
        public HashSet<string> Backup { get; set; } = new();
        public DateTime LastUpdated { get; set; }
        public TimeSpan MaxAge { get; set; } = TimeSpan.FromDays(90);
    }

    public bool ValidateWithBackup(string host, X509Certificate2 certificate)
    {
        if (!_pins.TryGetValue(host, out var pin))
            return false;

        var thumbprint = certificate.Thumbprint;

        // Check primary pins first
        if (pin.Primary.Contains(thumbprint))
            return true;

        // Check backup pins if primary fails
        if (pin.Backup.Contains(thumbprint))
        {
            // Log backup certificate usage for monitoring
            LogBackupCertificateUsage(host, thumbprint);
            return true;
        }

        return false;
    }

    private void LogBackupCertificateUsage(string host, string thumbprint)
    {
        // Implementation for monitoring backup certificate usage
    }
}
```

## Security Considerations

### Certificate Rotation Strategy

```csharp
public class CertificateRotationManager
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<CertificateRotationManager> _logger;

    public async Task<bool> UpdatePinnedCertificatesAsync()
    {
        try
        {
            // Fetch new certificate configurations from secure storage
            var newPins = await FetchCertificateConfigurationAsync();
            
            // Validate new certificates before applying
            if (await ValidateNewCertificatesAsync(newPins))
            {
                await ApplyCertificateUpdatesAsync(newPins);
                _logger.LogInformation("Certificate pins updated successfully");
                return true;
            }
            
            _logger.LogWarning("Certificate validation failed, keeping existing pins");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update certificate pins");
            return false;
        }
    }

    private async Task<Dictionary<string, HashSet<string>>> FetchCertificateConfigurationAsync()
    {
        // Implementation to fetch from Azure Key Vault, AWS Secrets Manager, etc.
        throw new NotImplementedException();
    }

    private async Task<bool> ValidateNewCertificatesAsync(Dictionary<string, HashSet<string>> newPins)
    {
        // Validate that new certificates are legitimate and accessible
        foreach (var (domain, thumbprints) in newPins)
        {
            foreach (var thumbprint in thumbprints)
            {
                if (!await TestCertificateConnectivityAsync(domain, thumbprint))
                    return false;
            }
        }
        return true;
    }

    private async Task<bool> TestCertificateConnectivityAsync(string domain, string thumbprint)
    {
        // Test connectivity with the new certificate
        throw new NotImplementedException();
    }

    private async Task ApplyCertificateUpdatesAsync(Dictionary<string, HashSet<string>> newPins)
    {
        // Apply the new certificate pins
        throw new NotImplementedException();
    }
}
```

### Secure Pin Storage

```csharp
public class SecurePinStorage
{
    private readonly ISecretManager _secretManager;
    private readonly IMemoryCache _cache;

    public async Task<HashSet<string>> GetPinnedCertificatesAsync(string domain)
    {
        var cacheKey = $"pins:{domain}";
        
        if (_cache.TryGetValue(cacheKey, out HashSet<string>? cachedPins))
            return cachedPins!;

        var pins = await _secretManager.GetSecretAsync($"certificate-pins-{domain}");
        var pinSet = pins.Split(',').ToHashSet();
        
        _cache.Set(cacheKey, pinSet, TimeSpan.FromMinutes(15));
        return pinSet;
    }

    public async Task UpdatePinnedCertificatesAsync(string domain, HashSet<string> pins)
    {
        var pinsString = string.Join(",", pins);
        await _secretManager.SetSecretAsync($"certificate-pins-{domain}", pinsString);
        
        // Invalidate cache
        _cache.Remove($"pins:{domain}");
    }
}
```

## Best Practices

### 1. Multiple Pin Strategy

Always pin multiple certificates to prevent service disruption:

```csharp
public class MultiPinStrategy
{
    private readonly Dictionary<string, PinConfiguration> _configurations = new()
    {
        ["api.example.com"] = new PinConfiguration
        {
            CurrentCertificate = "CURRENT_CERT_THUMBPRINT",
            BackupCertificates = new[]
            {
                "BACKUP_CERT_1_THUMBPRINT",
                "BACKUP_CERT_2_THUMBPRINT"
            },
            IntermediateCAs = new[]
            {
                "INTERMEDIATE_CA_THUMBPRINT"
            }
        }
    };

    public class PinConfiguration
    {
        public string CurrentCertificate { get; set; } = string.Empty;
        public string[] BackupCertificates { get; set; } = Array.Empty<string>();
        public string[] IntermediateCAs { get; set; } = Array.Empty<string>();
    }
}
```

### 2. Graceful Degradation

```csharp
public class GracefulDegradationPinning
{
    private readonly bool _strictMode;
    private readonly ILogger<GracefulDegradationPinning> _logger;

    public bool ValidateWithFallback(X509Certificate2 certificate, string host)
    {
        // Try pinning validation first
        if (ValidatePinnedCertificate(certificate, host))
            return true;

        if (_strictMode)
        {
            _logger.LogWarning("Strict mode: Rejecting non-pinned certificate for {Host}", host);
            return false;
        }

        // Fallback to standard CA validation in non-strict mode
        _logger.LogWarning("Fallback: Using standard CA validation for {Host}", host);
        return ValidateStandardCA(certificate);
    }

    private bool ValidatePinnedCertificate(X509Certificate2 certificate, string host)
    {
        // Pinning validation logic
        throw new NotImplementedException();
    }

    private bool ValidateStandardCA(X509Certificate2 certificate)
    {
        // Standard CA validation
        throw new NotImplementedException();
    }
}
```

### 3. Monitoring and Alerting

```csharp
public class CertificatePinningMonitor
{
    private readonly IMetrics _metrics;
    private readonly ILogger<CertificatePinningMonitor> _logger;

    public void RecordValidationAttempt(string host, string thumbprint, bool success)
    {
        _metrics.Counter("certificate_pinning_validations")
            .WithTag("host", host)
            .WithTag("success", success.ToString())
            .Increment();

        if (!success)
        {
            _logger.LogWarning(
                "Certificate pinning validation failed for {Host} with thumbprint {Thumbprint}",
                host, thumbprint);
            
            // Trigger alert for security team
            TriggerSecurityAlert(host, thumbprint);
        }
    }

    public void RecordCertificateExpiry(string host, DateTime expiryDate)
    {
        var daysUntilExpiry = (expiryDate - DateTime.UtcNow).Days;
        
        _metrics.Gauge("certificate_days_until_expiry")
            .WithTag("host", host)
            .Set(daysUntilExpiry);

        if (daysUntilExpiry <= 30)
        {
            _logger.LogWarning(
                "Certificate for {Host} expires in {Days} days",
                host, daysUntilExpiry);
        }
    }

    private void TriggerSecurityAlert(string host, string thumbprint)
    {
        // Implementation for security alerting
    }
}
```

## Common Pitfalls

### 1. Forgetting Certificate Rotation

**Problem:** Pinned certificates expire, causing service outages.

**Solution:** Implement automated certificate monitoring and rotation:

```csharp
public class CertificateExpiryMonitor : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<CertificateExpiryMonitor> _logger;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await CheckCertificateExpiry();
            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }

    private async Task CheckCertificateExpiry()
    {
        using var scope = _serviceProvider.CreateScope();
        var pinningService = scope.ServiceProvider.GetRequiredService<CertificatePinningService>();
        
        // Check all pinned certificates for expiry
        await pinningService.CheckExpiryDatesAsync();
    }
}
```

### 2. Insufficient Backup Pins

**Problem:** Single point of failure if the only pinned certificate becomes unavailable.

**Solution:** Always maintain multiple valid pins:

```csharp
public class RedundantPinning
{
    private const int MinimumPinsRequired = 2;

    public void ValidatePinConfiguration(Dictionary<string, HashSet<string>> pins)
    {
        foreach (var (domain, domainPins) in pins)
        {
            if (domainPins.Count < MinimumPinsRequired)
            {
                throw new InvalidOperationException(
                    $"Domain {domain} has insufficient backup pins. Minimum required: {MinimumPinsRequired}");
            }
        }
    }
}
```

### 3. Hardcoded Pins in Source Code

**Problem:** Pins in source code are difficult to update and pose security risks.

**Solution:** Use external configuration:

```csharp
public class ConfigurablePinning
{
    private readonly IOptionsMonitor<CertificatePinningOptions> _options;

    public ConfigurablePinning(IOptionsMonitor<CertificatePinningOptions> options)
    {
        _options = options;
    }

    public bool ValidateCertificate(string host, X509Certificate2 certificate)
    {
        var currentOptions = _options.CurrentValue;
        
        if (!currentOptions.DomainPins.TryGetValue(host, out var pins))
            return false;

        return pins.Contains(certificate.Thumbprint);
    }
}

public class CertificatePinningOptions
{
    public Dictionary<string, HashSet<string>> DomainPins { get; set; } = new();
    public bool StrictMode { get; set; } = true;
    public TimeSpan CacheTimeout { get; set; } = TimeSpan.FromMinutes(15);
}
```

## Advanced Scenarios

### 1. Dynamic Pin Updates

```csharp
public class DynamicPinManager
{
    private readonly IHubContext<PinUpdateHub> _hubContext;
    private readonly ConcurrentDictionary<string, HashSet<string>> _activePins = new();

    public async Task UpdatePinsAsync(string domain, HashSet<string> newPins)
    {
        _activePins.AddOrUpdate(domain, newPins, (_, _) => newPins);
        
        // Notify all connected clients about the update
        await _hubContext.Clients.All.SendAsync("PinsUpdated", domain, newPins);
    }

    public async Task<bool> ValidateAndUpdateAsync(string domain, X509Certificate2 certificate)
    {
        if (_activePins.TryGetValue(domain, out var pins) && 
            pins.Contains(certificate.Thumbprint))
        {
            return true;
        }

        // Attempt to fetch updated pins from remote source
        var updatedPins = await FetchLatestPinsAsync(domain);
        if (updatedPins != null)
        {
            await UpdatePinsAsync(domain, updatedPins);
            return updatedPins.Contains(certificate.Thumbprint);
        }

        return false;
    }

    private async Task<HashSet<string>?> FetchLatestPinsAsync(string domain)
    {
        // Implementation to fetch from remote pin server
        throw new NotImplementedException();
    }
}
```

### 2. Certificate Transparency Integration

```csharp
public class CertificateTransparencyValidator
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<CertificateTransparencyValidator> _logger;

    public async Task<bool> ValidateAgainstCTLogsAsync(X509Certificate2 certificate)
    {
        try
        {
            // Query Certificate Transparency logs
            var ctResponse = await QueryCTLogsAsync(certificate);
            return ctResponse.IsValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to validate certificate against CT logs");
            return false;
        }
    }

    private async Task<CTValidationResponse> QueryCTLogsAsync(X509Certificate2 certificate)
    {
        // Implementation to query CT logs
        throw new NotImplementedException();
    }

    public class CTValidationResponse
    {
        public bool IsValid { get; set; }
        public DateTime LoggedAt { get; set; }
        public string LogId { get; set; } = string.Empty;
    }
}
```

### 3. Multi-Environment Pin Management

```csharp
public class EnvironmentAwarePinning
{
    private readonly IWebHostEnvironment _environment;
    private readonly Dictionary<string, Dictionary<string, HashSet<string>>> _environmentPins;

    public EnvironmentAwarePinning(IWebHostEnvironment environment)
    {
        _environment = environment;
        _environmentPins = new Dictionary<string, Dictionary<string, HashSet<string>>>
        {
            ["Development"] = new()
            {
                ["api.dev.example.com"] = new HashSet<string> { "DEV_CERT_THUMBPRINT" }
            },
            ["Staging"] = new()
            {
                ["api.staging.example.com"] = new HashSet<string> { "STAGING_CERT_THUMBPRINT" }
            },
            ["Production"] = new()
            {
                ["api.example.com"] = new HashSet<string> 
                { 
                    "PROD_CERT_THUMBPRINT_1",
                    "PROD_CERT_THUMBPRINT_2" 
                }
            }
        };
    }

    public bool ValidateForCurrentEnvironment(string host, X509Certificate2 certificate)
    {
        var environmentName = _environment.EnvironmentName;
        
        if (!_environmentPins.TryGetValue(environmentName, out var envPins))
            return false;

        if (!envPins.TryGetValue(host, out var hostPins))
            return false;

        return hostPins.Contains(certificate.Thumbprint);
    }
}
```

## Testing and Validation

### 1. Unit Testing Certificate Pinning

```csharp
[TestClass]
public class CertificatePinningTests
{
    private CertificatePinningService _service;
    private Mock<ILogger<CertificatePinningService>> _mockLogger;

    [TestInitialize]
    public void Setup()
    {
        _mockLogger = new Mock<ILogger<CertificatePinningService>>();
        _service = new CertificatePinningService(_mockLogger.Object);
    }

    [TestMethod]
    public void ValidateCertificate_WithValidPin_ReturnsTrue()
    {
        // Arrange
        var certificate = CreateTestCertificate("VALID_THUMBPRINT");
        
        // Act
        var result = _service.ValidateCertificate(certificate);
        
        // Assert
        Assert.IsTrue(result);
    }

    [TestMethod]
    public void ValidateCertificate_WithInvalidPin_ReturnsFalse()
    {
        // Arrange
        var certificate = CreateTestCertificate("INVALID_THUMBPRINT");
        
        // Act
        var result = _service.ValidateCertificate(certificate);
        
        // Assert
        Assert.IsFalse(result);
    }

    private X509Certificate2 CreateTestCertificate(string thumbprint)
    {
        // Create test certificate with specified thumbprint
        throw new NotImplementedException();
    }
}
```

### 2. Integration Testing

```csharp
[TestClass]
public class CertificatePinningIntegrationTests
{
    private TestServer _server;
    private HttpClient _client;

    [TestInitialize]
    public void Setup()
    {
        var builder = new WebHostBuilder()
            .UseStartup<TestStartup>()
            .ConfigureServices(services =>
            {
                services.AddSingleton<CertificatePinningService>();
            });

        _server = new TestServer(builder);
        _client = _server.CreateClient();
    }

    [TestMethod]
    public async Task HttpClient_WithValidPin_SucceedsConnection()
    {
        // Arrange
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/test");
        
        // Act
        var response = await _client.SendAsync(request);
        
        // Assert
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
    }

    [TestCleanup]
    public void Cleanup()
    {
        _client?.Dispose();
        _server?.Dispose();
    }
}
```

### 3. Load Testing with Pinning

```csharp
public class CertificatePinningLoadTest
{
    private readonly CertificatePinningService _pinningService;
    private readonly PerformanceCounter _validationCounter;

    public async Task<LoadTestResults> RunLoadTestAsync(int concurrentRequests, TimeSpan duration)
    {
        var tasks = new List<Task<ValidationResult>>();
        var cancellationTokenSource = new CancellationTokenSource(duration);

        for (int i = 0; i < concurrentRequests; i++)
        {
            tasks.Add(RunValidationLoopAsync(cancellationTokenSource.Token));
        }

        var results = await Task.WhenAll(tasks);
        
        return new LoadTestResults
        {
            TotalValidations = results.Sum(r => r.TotalAttempts),
            SuccessfulValidations = results.Sum(r => r.SuccessfulAttempts),
            AverageResponseTime = results.Average(r => r.AverageResponseTime),
            ErrorRate = results.Average(r => r.ErrorRate)
        };
    }

    private async Task<ValidationResult> RunValidationLoopAsync(CancellationToken cancellationToken)
    {
        var result = new ValidationResult();
        
        while (!cancellationToken.IsCancellationRequested)
        {
            var stopwatch = Stopwatch.StartNew();
            
            try
            {
                var certificate = await GetTestCertificateAsync();
                var isValid = _pinningService.ValidateCertificate(certificate);
                
                result.TotalAttempts++;
                if (isValid) result.SuccessfulAttempts++;
                
                result.TotalResponseTime += stopwatch.ElapsedMilliseconds;
            }
            catch (Exception)
            {
                result.Errors++;
            }
            finally
            {
                stopwatch.Stop();
            }
        }

        result.AverageResponseTime = result.TotalResponseTime / result.TotalAttempts;
        result.ErrorRate = (double)result.Errors / result.TotalAttempts;
        
        return result;
    }

    private async Task<X509Certificate2> GetTestCertificateAsync()
    {
        // Implementation to get test certificate
        throw new NotImplementedException();
    }

    public class ValidationResult
    {
        public int TotalAttempts { get; set; }
        public int SuccessfulAttempts { get; set; }
        public int Errors { get; set; }
        public long TotalResponseTime { get; set; }
        public double AverageResponseTime { get; set; }
        public double ErrorRate { get; set; }
    }

    public class LoadTestResults
    {
        public int TotalValidations { get; set; }
        public int SuccessfulValidations { get; set; }
        public double AverageResponseTime { get; set; }
        public double ErrorRate { get; set; }
    }
}
```

## Production Deployment

### 1. Configuration Management

```json
{
  "CertificatePinning": {
    "StrictMode": true,
    "CacheTimeout": "00:15:00",
    "DomainPins": {
      "api.example.com": [
        "A1B2C3D4E5F6789012345678901234567890ABCD",
        "B2C3D4E5F6789012345678901234567890ABCDE1"
      ],
      "secure.example.com": [
        "C3D4E5F6789012345678901234567890ABCDEF2"
      ]
    },
    "MonitoringEnabled": true,
    "AlertThresholds": {
      "FailureRate": 0.05,
      "ExpiryWarningDays": 30
    }
  }
}
```

### 2. Deployment Checklist

**Pre-Deployment:**
- [ ] Verify all pinned certificates are valid and accessible
- [ ] Test certificate pinning in staging environment
- [ ] Prepare rollback plan for pin updates
- [ ] Configure monitoring and alerting
- [ ] Document certificate rotation procedures

**During Deployment:**
- [ ] Deploy with gradual rollout (canary deployment)
- [ ] Monitor error rates and response times
- [ ] Verify certificate validation is working correctly
- [ ] Check logs for any pinning failures

**Post-Deployment:**
- [ ] Monitor application health metrics
- [ ] Verify all external API calls are successful
- [ ] Set up automated certificate expiry monitoring
- [ ] Document any issues and resolutions

### 3. Monitoring and Observability

```csharp
public class CertificatePinningTelemetry
{
    private readonly IMetrics _metrics;
    private readonly ILogger<CertificatePinningTelemetry> _logger;

    public void RecordValidation(string host, bool success, TimeSpan duration)
    {
        _metrics.Counter("certificate_pinning_validations_total")
            .WithTag("host", host)
            .WithTag("result", success ? "success" : "failure")
            .Increment();

        _metrics.Histogram("certificate_pinning_validation_duration")
            .WithTag("host", host)
            .Record(duration.TotalMilliseconds);

        if (!success)
        {
            _logger.LogWarning("Certificate pinning validation failed for host: {Host}", host);
        }
    }

    public void RecordCertificateExpiry(string host, TimeSpan timeUntilExpiry)
    {
        _metrics.Gauge("certificate_expiry_days")
            .WithTag("host", host)
            .Set(timeUntilExpiry.TotalDays);

        if (timeUntilExpiry.TotalDays <= 30)
        {
            _logger.LogWarning(
                "Certificate for {Host} expires in {Days} days", 
                host, timeUntilExpiry.TotalDays);
        }
    }
}
```

### 4. Disaster Recovery

```csharp
public class CertificatePinningDisasterRecovery
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<CertificatePinningDisasterRecovery> _logger;

    public async Task<bool> ExecuteEmergencyPinUpdateAsync(string domain, string newThumbprint)
    {
        try
        {
            // Validate the emergency certificate
            if (!await ValidateEmergencyCertificateAsync(domain, newThumbprint))
            {
                _logger.LogError("Emergency certificate validation failed for {Domain}", domain);
                return false;
            }

            // Update pins with emergency certificate
            await UpdateEmergencyPinsAsync(domain, newThumbprint);
            
            // Notify operations team
            await NotifyEmergencyUpdateAsync(domain, newThumbprint);
            
            _logger.LogInformation("Emergency pin update completed for {Domain}", domain);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Emergency pin update failed for {Domain}", domain);
            return false;
        }
    }

    private async Task<bool> ValidateEmergencyCertificateAsync(string domain, string thumbprint)
    {
        // Validate that the emergency certificate is legitimate
        throw new NotImplementedException();
    }

    private async Task UpdateEmergencyPinsAsync(string domain, string thumbprint)
    {
        // Update certificate pins in secure storage
        throw new NotImplementedException();
    }

    private async Task NotifyEmergencyUpdateAsync(string domain, string thumbprint)
    {
        // Send notifications to operations team
        throw new NotImplementedException();
    }
}
```

## Conclusion

Certificate pinning is a powerful security technique that significantly enhances the security posture of .NET applications by preventing man-in-the-middle attacks. However, it requires careful implementation, thorough testing, and ongoing maintenance to be effective.

Key takeaways:

1. **Always use multiple pins** to prevent service disruption
2. **Implement proper monitoring** to detect pinning failures
3. **Plan for certificate rotation** before certificates expire
4. **Test thoroughly** in staging environments
5. **Have a disaster recovery plan** for emergency pin updates
6. **Use secure storage** for pin configurations
7. **Monitor certificate expiry dates** proactively

When implemented correctly, certificate pinning provides an additional layer of security that complements traditional SSL/TLS validation, making your applications more resilient against sophisticated attacks.

Remember that certificate pinning is not a silver bullet – it should be part of a comprehensive security strategy that includes other security measures such as proper authentication, authorization, input validation, and regular security audits.