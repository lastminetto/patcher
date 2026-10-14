using System.Text;
using PvePatcher.Core;
using PvePatcher.Targets;

namespace PvePatcher.Targets.Tests;

public class ParserTests
{
    private const string DebianList =
        "I\tbash\tbash\t5.2.15-2+b7\t5.2.15-2\tamd64\n" +
        "I\tlibc6:amd64\tglibc\t2.36-9+deb12u4\t2.36-9+deb12u4\tamd64\n" +
        "I\tlibc6:i386\tglibc\t2.36-9+deb12u4\t2.36-9+deb12u4\ti386\n" +
        "I\ttzdata\ttzdata\t2024a-0+deb12u1\t2024a-0+deb12u1\tall\n" +
        "I\tlinux-image-amd64\tlinux-signed-amd64\t6.1.99-1\t6.1.99+1\tamd64\n" +
        "U\tlibc6:amd64\t2.36-9+deb12u4\t2.36-9+deb12u7\tamd64\t0\n" +
        "U\tlinux-image-amd64\t6.1.99-1\t6.1.106-3\tamd64\t1\n";

    [Fact]
    public void Apt_binNMU_e_multiarch()
    {
        var (inst, pend) = AgentOutputParser.ParseList(DebianList);
        Assert.Equal(5, inst.Count);
        var bash = inst[0];
        Assert.Equal("5.2.15-2+b7", bash.Version);
        Assert.Equal("5.2.15-2", bash.SourceVersion);
        Assert.Equal("glibc", inst[1].SourceName);
        Assert.Equal("libc6:amd64", inst[1].Name);
        Assert.Equal("all", inst[3].Arch);

        Assert.Equal(2, pend.Count);
        Assert.Equal("glibc", pend[0].SourceName);
        Assert.False(pend[0].HeldBack);
        Assert.Equal("2.36-9+deb12u7", pend[0].CandidateVersion);
        Assert.True(pend[1].HeldBack);
        Assert.Equal("linux-signed-amd64", pend[1].SourceName);
    }

    [Fact]
    public void Dnf_epoch_e_source_rpm()
    {
        const string o =
            "I\tbash\tbash\t5.1.8-6.el9\t5.1.8-6.el9\tx86_64\n" +
            "I\tbind-libs\tbind\t32:9.16.23-1.el9\t32:9.16.23-1.el9\tx86_64\n" +
            "I\tkernel-core\tkernel\t5.14.0-427.el9\t5.14.0-427.el9\tx86_64\n" +
            "U\tbind-libs\t32:9.16.23-1.el9\t32:9.16.23-2.el9\tx86_64\t0\n";
        var (inst, pend) = AgentOutputParser.ParseList(o);
        Assert.Equal("32:9.16.23-1.el9", inst[1].Version);
        Assert.Equal("bind", inst[1].SourceName);
        var u = Assert.Single(pend);
        Assert.Equal("bind", u.SourceName);
        Assert.Equal("32:9.16.23-2.el9", u.CandidateVersion);
    }

    [Fact]
    public void Apk_origin_diferente_do_nome()
    {
        const string o =
            "I\tlibssl3\topenssl\t3.3.1-r0\t3.3.1-r0\tx86_64\n" +
            "I\tmusl\tmusl\t1.2.5-r0\t1.2.5-r0\tx86_64\n" +
            "U\tlibssl3\t3.3.1-r0\t3.3.2-r0\tx86_64\t0\n";
        var (inst, pend) = AgentOutputParser.ParseList(o);
        Assert.Equal("openssl", inst[0].SourceName);
        Assert.Equal("openssl", Assert.Single(pend).SourceName);
    }

    [Fact]
    public void Linhas_vazias_e_crlf_sao_toleradas_e_campos_vazios_viram_defaults()
    {
        var (inst, pend) = AgentOutputParser.ParseList("\r\nI\tfoo\t\t1.0\t\t\r\n\nU\tbar\t1\t2\t\t0\r\n");
        var p = Assert.Single(inst);
        Assert.Equal("foo", p.SourceName);
        Assert.Equal("1.0", p.SourceVersion);
        Assert.Null(p.Arch);
        Assert.Null(Assert.Single(pend).Arch);
    }

    [Fact]
    public void OsInfo_debian_e_alma()
    {
        var (os, kernel) = AgentOutputParser.ParseOsInfo(
            "O\tID\tdebian\nO\tVERSION_ID\t12\nO\tVERSION_CODENAME\tbookworm\nO\tPRETTY_NAME\tDebian GNU/Linux 12 (bookworm)\nK\tkernel\t6.1.0-25-amd64\n");
        Assert.Equal(Distro.Debian, os.Distro);
        Assert.Equal("bookworm", os.Codename);
        Assert.Equal(OsFamily.Apt, os.Family);
        Assert.Equal("6.1.0-25-amd64", kernel);

        (os, _) = AgentOutputParser.ParseOsInfo("O\tID\talmalinux\nO\tVERSION_ID\t9.4\nO\tVERSION_CODENAME\t\nO\tPRETTY_NAME\tAlmaLinux 9.4\nK\tkernel\t5.14.0\n");
        Assert.Equal(Distro.AlmaLinux, os.Distro);
        Assert.Null(os.Codename);
        Assert.Equal("9.4", os.VersionId);
    }

    [Theory]
    [InlineData("yes\n", true)]
    [InlineData("no", false)]
    public void RebootRequired(string text, bool expected) =>
        Assert.Equal(expected, AgentOutputParser.ParseRebootRequired(text));

    [Fact]
    public void RebootRequired_invalido_lanca() =>
        Assert.Throws<TargetException>(() => AgentOutputParser.ParseRebootRequired("talvez"));
}

public class ShellQuoteTests
{
    [Theory]
    [InlineData("abc", "'abc'")]
    [InlineData("it's", "'it'\\''s'")]
    [InlineData("a b;$(x)", "'a b;$(x)'")]
    [InlineData("", "''")]
    public void Quote(string input, string expected) => Assert.Equal(expected, ShellQuote.Quote(input));

    [Fact]
    public void Comando_do_agente()
    {
        Assert.Equal("sudo -n /usr/local/sbin/patcher-agent 'list'", ShellQuote.BuildAgentCommand("list", []));
        Assert.Equal(
            "sudo -n /usr/local/sbin/patcher-agent 'upgrade-pkgs' 'libc6:amd64' 'x'\\''y'",
            ShellQuote.BuildAgentCommand("upgrade-pkgs", ["libc6:amd64", "x'y"]));
    }
}

public class HostKeyFingerprintTests
{
    [Fact]
    public void Formato_openssh_sem_padding()
    {
        // printf 'hostkey-blob' | openssl dgst -sha256 -binary | base64 (sem '=')
        Assert.Equal("SHA256:rWY+leCBSRl5C0XTsbDMAPEhfkrmYERyf2Nm6sk47XE", HostKeyFingerprint.Sha256(Encoding.ASCII.GetBytes("hostkey-blob")));
    }
}

public class SessionAndScriptTests
{
    [Theory]
    [InlineData(1, "sudo: a password is required", true)]
    [InlineData(127, "sh: 1: /usr/local/sbin/patcher-agent: not found", true)]
    [InlineData(1, "sudo: /usr/local/sbin/patcher-agent: command not found", true)]
    [InlineData(1, "apt-get: E: Unable to lock", false)]
    [InlineData(100, "something not found", false)]
    public void Detecta_agent_ausente(int exit, string stderr, bool expected) =>
        Assert.Equal(expected, SshTargetSession.LooksLikeMissingAgent(exit, stderr));

    [Fact]
    public void Bootstrap_embute_o_agent()
    {
        var script = BootstrapScript.Render();
        Assert.DoesNotContain(BootstrapScript.Placeholder, script);
        Assert.Contains("cmd_upgrade_pkgs()", script);
        Assert.StartsWith("#!/bin/sh", script);
        Assert.DoesNotContain("\r", script);
    }

    [Fact]
    public void Bootstrap_rejeita_agent_com_terminador()
    {
        Assert.Throws<ArgumentException>(() => BootstrapScript.Build("x\n@@PATCHER_AGENT@@\n", "a\nPATCHER_AGENT_EOF\nb"));
    }

    [Fact]
    public void Comando_de_bootstrap_cita_valores()
    {
        var cmd = BootstrapScript.Command("https://p.example/bootstrap-vm.sh", "ssh-ed25519 AAAA patcher@x", fromCidr: "10.0.0.0/8");
        Assert.Equal(
            "curl -fsSL 'https://p.example/bootstrap-vm.sh' | sh -s -- --pubkey 'ssh-ed25519 AAAA patcher@x' --user 'patcher' --from '10.0.0.0/8'",
            cmd);
    }
}
