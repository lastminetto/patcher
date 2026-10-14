using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace PvePatcher.Web.Data;

/// <summary>Opções JSON usadas nas colunas JSON do SQLite.</summary>
public static class Json
{
    public static readonly JsonSerializerOptions Options = Create();

    private static JsonSerializerOptions Create()
    {
        var o = new JsonSerializerOptions();
        o.Converters.Add(new JsonStringEnumConverter());
        o.Converters.Add(new IPAddressConverter());
        return o;
    }

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);

    public static T? Deserialize<T>(string? json) where T : class =>
        string.IsNullOrWhiteSpace(json) ? null : JsonSerializer.Deserialize<T>(json, Options);

    private sealed class IPAddressConverter : JsonConverter<IPAddress>
    {
        public override IPAddress? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            IPAddress.TryParse(reader.GetString(), out var ip) ? ip : null;

        public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options) =>
            writer.WriteStringValue(value.ToString());
    }
}
