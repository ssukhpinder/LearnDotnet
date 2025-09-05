using Microsoft.AspNetCore.Mvc;
using CertificatePinningAuthSample.Services;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace CertificatePinningAuthSample.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CertificateController : ControllerBase
{
    private readonly CertificatePinningService _pinningService;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<CertificateController> _logger;

    public CertificateController(CertificatePinningService pinningService, 
        IHttpClientFactory httpClientFactory, ILogger<CertificateController> logger)
    {
        _pinningService = pinningService;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    [HttpGet("validate/{url}")]
    public async Task<IActionResult> ValidateUrl(string url)
    {
        try
        {
            var handler = new HttpClientHandler();
            handler.ServerCertificateCustomValidationCallback = _pinningService.ValidateServerCertificate;
            
            using var client = new HttpClient(handler);
            var response = await client.GetAsync($"https://{url}");
            
            return Ok(new { 
                Url = url, 
                Status = "Certificate validation passed",
                StatusCode = response.StatusCode 
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Certificate validation failed for {Url}", url);
            return BadRequest(new { 
                Url = url, 
                Status = "Certificate validation failed", 
                Error = ex.Message 
            });
        }
    }

    [HttpPost("pin")]
    public IActionResult PinCertificate([FromBody] PinCertificateRequest request)
    {
        try
        {
            _pinningService.AddPinnedCertificate(request.Thumbprint);
            return Ok(new { Status = "Certificate pinned successfully", Thumbprint = request.Thumbprint });
        }
        catch (Exception ex)
        {
            return BadRequest(new { Status = "Failed to pin certificate", Error = ex.Message });
        }
    }

    [HttpGet("info")]
    public IActionResult GetInfo()
    {
        return Ok(new
        {
            Message = "Certificate Pinning Authentication Sample",
            Description = "This API demonstrates certificate pinning for secure connections",
            Endpoints = new[]
            {
                "GET /api/certificate/validate/{url} - Validate a URL against pinned certificates",
                "POST /api/certificate/pin - Pin a new certificate thumbprint",
                "GET /api/certificate/info - Get API information"
            }
        });
    }
}

public record PinCertificateRequest(string Thumbprint);