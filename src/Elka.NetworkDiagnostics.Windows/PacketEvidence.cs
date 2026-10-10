using System.Net;
using System.Xml;
using System.Xml.Linq;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Windows;

public static class PacketEvidence
{
    public static List<PacketDrop> MatchingDrops(string xml, string local, string peer, int port, DateTimeOffset since)
    {
        if (xml.StartsWith("No 5152 event was returned", StringComparison.Ordinal)) return [];
        using var reader = XmlReader.Create(new StringReader("<Events>" + xml + "</Events>"), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 100_000 });
        var document = XDocument.Load(reader);
        List<PacketDrop> matches = [];
        XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
        if (!document.Root!.Elements(ns + "Event").Any()) throw new InvalidDataException("No readable Windows event XML was present in the capture output.");
        foreach (var e in document.Root!.Elements(ns + "Event"))
        {
            var system = e.Element(ns + "System");
            if (system?.Element(ns + "EventID")?.Value != "5152" ||
                !DateTimeOffset.TryParse((string?)system.Element(ns + "TimeCreated")?.Attribute("SystemTime"), out var time) || time < since || time > DateTimeOffset.UtcNow.AddMinutes(1)) continue;
            var data = e.Element(ns + "EventData")?.Elements(ns + "Data").Where(x => x.Attribute("Name") != null)
                .GroupBy(x => (string)x.Attribute("Name")!).ToDictionary(g => g.Key, g => g.First().Value) ?? [];
            string Value(string key) => data.GetValueOrDefault(key, "");
            string source = Normalize(Value("SourceAddress")), destination = Normalize(Value("DestAddress"));
            if (!((source == local && destination == peer) || (source == peer && destination == local)) ||
                !int.TryParse(Value("SourcePort"), out int sourcePort) || !int.TryParse(Value("DestPort"), out int destinationPort) ||
                (sourcePort != port && destinationPort != port)) continue;
            string protocol = Value("Protocol") switch { "6" => "TCP", "17" => "UDP", _ => "" };
            if (protocol != "") matches.Add(new(protocol, source, destination, sourcePort, destinationPort, Value("FilterRTID"),
                time, Value("FilterOrigin"), Value("LayerRTID"), Value("InterfaceIndex")));
        }
        return matches;
    }
    private static string Normalize(string value) => IPAddress.TryParse(value, out var address) ? (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString() : "";
}
