using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using PvePatcher.Web.Services;

namespace PvePatcher.Web.Tests;

public class CertificatePinTests
{
    private static (string Pem, string ExpectedPin) SelfSigned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest("CN=patcher", key, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        // Mesmo que o openssl calcula: SHA-256 da SubjectPublicKeyInfo em DER.
        var expected = Convert.ToBase64String(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        return (cert.ExportCertificatePem(), expected);
    }

    [Fact]
    public void Pin_e_o_sha256_da_chave_publica()
    {
        var (pem, expected) = SelfSigned();
        Assert.Equal(expected, AppCertificatePin.Compute(pem));
    }

    [Fact]
    public void Pin_le_o_pem_do_kestrel_e_sem_certificado_devolve_null()
    {
        var (pem, expected) = SelfSigned();
        var path = Path.Combine(Path.GetTempPath(), $"pin-{Guid.NewGuid():N}.pem");
        File.WriteAllText(path, pem);
        try
        {
            var withCert = new AppCertificatePin(
                new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Kestrel:Certificates:Default:Path"] = path }).Build(),
                NullLogger<AppCertificatePin>.Instance);
            Assert.Equal(expected, withCert.Current());

            var without = new AppCertificatePin(new ConfigurationBuilder().Build(), NullLogger<AppCertificatePin>.Instance);
            Assert.Null(without.Current());
        }
        finally { File.Delete(path); }
    }
}

public class BootstrapLinkTests
{
    [Theory]
    [InlineData("https://patcher.minetto.dev.br/", "http://172.22.104.31:8080", "https://10.0.0.1:8443/", "https://patcher.minetto.dev.br")]
    [InlineData("", "http://172.22.104.31:8080/", "https://10.0.0.1:8443/", "http://172.22.104.31:8080")]
    [InlineData(null, "", "https://10.0.0.1:8443/", "https://10.0.0.1:8443")]
    public void Url_tela_vence_config_que_vence_a_pagina(string? ui, string? config, string page, string expected) =>
        Assert.Equal(expected, BootstrapLink.BaseUrl(ui, config, page));

    [Theory]
    [InlineData("https://x", "", true, true)]
    [InlineData("https://x", "", false, false)]
    [InlineData("https://x", "ca", true, false)]
    [InlineData("https://x", "pin", false, true)]
    [InlineData("http://x:8080", "pin", true, false)] // sem TLS não há o que pinar
    public void Pin(string url, string tls, bool config, bool expected) =>
        Assert.Equal(expected, BootstrapLink.UsePin(url, tls, config));

    [Theory]
    [InlineData("https://patcher.minetto.dev.br/", true, "https://patcher.minetto.dev.br")]
    [InlineData("  https://p.example:8443/app/ ", true, "https://p.example:8443/app")]
    [InlineData("", true, "")]
    [InlineData("patcher.minetto.dev.br", false, "")]
    [InlineData("ftp://p.example", false, "")]
    [InlineData("https://p.example/?x=1", false, "")]
    public void Normaliza_url(string value, bool ok, string expected)
    {
        Assert.Equal(ok, BootstrapLink.TryNormalize(value, out var n, out var err));
        if (ok) Assert.Equal(expected, n); else Assert.NotNull(err);
    }
}
