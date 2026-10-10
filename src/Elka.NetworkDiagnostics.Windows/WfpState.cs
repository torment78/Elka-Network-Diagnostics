using System.Globalization;
using System.Xml;
using System.Xml.Linq;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Windows;

public record WfpStateFilter(WfpFilterContext Context, string Signature);
public record WfpStateSnapshot(DateTimeOffset Time, Dictionary<string, WfpStateFilter> Filters);

public static class WfpState
{
    public const int CharacterLimit = 16 * 1024 * 1024;

    public static WfpStateSnapshot Read(string xml)
    {
        if (xml.Length > CharacterLimit) throw new InvalidDataException("WFP state exceeds the analysis limit.");
        // netsh writes an XML declaration followed by wfpstate AND firewallState roots.
        // Wrap that bounded fragment, without allowing external entities or DTDs.
        xml = xml.TrimStart('\uFEFF', ' ', '\r', '\n', '\t');
        if (xml.StartsWith("<?xml", StringComparison.Ordinal))
        {
            int end = xml.IndexOf("?>", StringComparison.Ordinal);
            if (end < 0 || end > 256) throw new InvalidDataException("Invalid WFP XML declaration.");
            xml = xml[(end + 2)..];
        }
        using var reader = XmlReader.Create(new StringReader("<capture>" + xml + "</capture>"),
            new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = CharacterLimit + 32 });
        var document = XDocument.Load(reader);
        var states = document.Root!.Elements("wfpstate").ToArray();
        if (states.Length != 1 || !DateTimeOffset.TryParse(states[0].Element("timeStamp")?.Value,
            CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var time))
            throw new InvalidDataException("WFP state has no unique timestamped state root.");
        var state = states[0];
        static string Value(XElement? node, string name) => node?.Element(name)?.Value.Trim() ?? "";
        static string Name(XElement? node) => Value(node?.Element("displayData"), "name");
        static Dictionary<string, XElement> Unique(IEnumerable<XElement> items, string key) => items
            .Where(x => Value(x, key) != "").GroupBy(x => Value(x, key), StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() == 1).ToDictionary(g => g.Key, g => g.Single(), StringComparer.OrdinalIgnoreCase);
        var providers = Unique(state.Element("providers")?.Elements("item") ?? [], "providerKey");
        var layers = Unique(state.Element("layers")?.Elements("item").Elements("layer") ?? [], "layerKey");
        var callouts = Unique(state.Descendants("callouts").Elements("item"), "calloutKey");
        var filters = Unique(state.Descendants("filters").Elements("item"), "filterId");
        Dictionary<string, WfpStateFilter> result = new(StringComparer.Ordinal);
        foreach (var (id, filter) in filters)
        {
            var provider = providers.GetValueOrDefault(Value(filter, "providerKey"));
            var layer = layers.GetValueOrDefault(Value(filter, "layerKey"));
            var action = filter.Element("action");
            var callout = callouts.GetValueOrDefault(Value(action, "filterType"));
            string Known(string value) => value == "" ? "not recorded" : value;
            var context = new WfpFilterContext(Known(Name(filter)), Known(Name(provider)), Known(Value(provider, "serviceName")),
                Known(Name(layer) == "" ? Value(filter, "layerKey") : Name(layer)), Value(layer, "layerId"), Known(Value(action, "type")), Known(Name(callout)));
            // Full filter configuration must agree, not just its friendly name or runtime ID.
            result.Add(id, new(context, filter.ToString(SaveOptions.DisableFormatting)));
        }
        return new(time, result);
    }

    public static PacketDrop Corroborate(PacketDrop drop, WfpStateSnapshot? before, WfpStateSnapshot? after)
    {
        var cleared = drop with { Context = null };
        if (before == null || after == null || !drop.Time.HasValue || before.Time > drop.Time || after.Time < drop.Time ||
            after.Time < before.Time || after.Time - before.Time > TimeSpan.FromMinutes(5) ||
            !before.Filters.TryGetValue(drop.FilterId, out var first) || !after.Filters.TryGetValue(drop.FilterId, out var last) ||
            first != last || (drop.LayerId != "" && first.Context.LayerId != drop.LayerId)) return cleared;
        return cleared with { Context = first.Context };
    }
}
