using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using Elka.NetworkDiagnostics.Core;

namespace Elka.NetworkDiagnostics.Windows;

public record UdpTraceResult(List<PacketSnapshot> Snapshots, int SnapshotHeaders, bool LimitReached)
{
    public int MatchedSnapshots { get; init; }
    public string LimitReason { get; init; } = "";
    public string Summary => $"{MatchedSnapshots} UDP snapshot(s) matched this scan's recorded test IDs, sequence ranges, addresses and destination ports; " +
        $"{Snapshots.Count} retained; {SnapshotHeaders} snapshot header(s) examined. " +
        (LimitReached ? "Partial analysis: " + LimitReason : "Exported text examined to the end.") +
        " Unmatched or unsupported payload formats remain unobserved. Truncated capture headers do not verify full payloads.";
}

public static class UdpPacketTrace
{
    private static readonly Regex Header = new(@"\bPktGroupId\s+((?:0x)?[0-9a-f]+)\s*,?\s+PktNumber\s+(\d+)\b", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);
    private static readonly Regex HexLine = new(@"^\s*(?:0x)?([0-9a-f]{4,8})\s*:\s*(.*)$|^\s*([0-9a-f]{4,8})\s{2,}(.*)$", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);
    private static readonly Regex Fields = new(@"\b(PktGroupId|PktNumber|Appearance|Direction|Type|Component|Edge|Filter|DropReason|DropLocation|OriginalSize|LoggedSize)\s+", RegexOptions.NonBacktracking);

    public static UdpTraceResult Read(TextReader reader, IReadOnlyList<FlowObservation> tests,
        long characterLimit = TraceTextReader.CharacterLimit, int snapshotLimit = 10_000, CancellationToken cancellationToken = default)
    {
        if (snapshotLimit < 1) throw new ArgumentOutOfRangeException(nameof(snapshotLimit));
        var input = new TraceTextReader(reader, characterLimit, cancellationToken);
        List<PacketSnapshot> snapshots = []; int headers = 0, matched = 0;
        Stack<int> ordinary = [];
        string? header = null; List<byte> bytes = []; bool invalidHex = false;
        void Finish()
        {
            if (header == null || invalidHex || !int.TryParse(Field(header, "LoggedSize"), out int logged) || logged != bytes.Count ||
                !TryIdentify(bytes.ToArray(), tests, out var identity)) return;
            var match = Header.Match(header);
            if (!int.TryParse(Field(header, "Component"), out int component) || !int.TryParse(Field(header, "Appearance"), out int appearance) ||
                !int.TryParse(match.Groups[2].Value, out int packetNumber)) return;
            string drop = Field(header, "DropReason");
            string numericDrop = drop.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? drop[2..] : drop;
            if (drop.Equals("None", StringComparison.OrdinalIgnoreCase) ||
                uint.TryParse(numericDrop, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out uint code) && code == 0) drop = "";
            if (drop == "" && Regex.IsMatch(header, @"\bDrop[:\s]", RegexOptions.IgnoreCase | RegexOptions.NonBacktracking)) drop = "unspecified reason";
            var snapshot = new PacketSnapshot(identity.TestId, identity.Sequence, component, appearance, match.Groups[1].Value, packetNumber, Field(header, "Direction"), drop);
            matched++;
            if (snapshots.Count < snapshotLimit)
            {
                if (drop == "") ordinary.Push(snapshots.Count);
                snapshots.Add(snapshot);
            }
            // Keep scanning after the detail budget is full. A late explicit drop
            // takes priority over an ordinary observation; it must not be hidden.
            else if (drop != "" && ordinary.TryPop(out int index)) snapshots[index] = snapshot;
        }
        foreach (string line in input.Lines())
        {
            if (Header.IsMatch(line)) { Finish(); headers++; header = line; bytes.Clear(); invalidHex = false; continue; }
            // A new timestamped event ends the prior packet even when it has no packet fields.
            if (line.TrimStart().StartsWith('[')) { Finish(); header = null; bytes.Clear(); continue; }
            if (header == null) continue;
            var hex = HexLine.Match(line);
            if (!hex.Success) continue;
            string offsetText = hex.Groups[1].Success ? hex.Groups[1].Value : hex.Groups[3].Value;
            string body = hex.Groups[1].Success ? hex.Groups[2].Value : hex.Groups[4].Value;
            if (!int.TryParse(offsetText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int offset) || offset != bytes.Count) { invalidHex = true; continue; }
            // ASCII decorations must not be interpreted as bytes, even if they contain hex letters.
            body = body.Split('|')[0];
            int rowBytes = 0;
            foreach (string word in body.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            {
                if (word.Length is not (2 or 4) || !word.All(Uri.IsHexDigit)) break;
                if (rowBytes + word.Length / 2 > 16) break;
                if (bytes.Count >= 2048) { invalidHex = true; break; }
                bytes.AddRange(Convert.FromHexString(word));
                rowBytes += word.Length / 2;
            }
        }
        Finish();
        string reason = input.LimitReason;
        if (matched > snapshots.Count) reason += (reason == "" ? "" : " ") +
            $"{matched - snapshots.Count} matching snapshot details were omitted from the {snapshotLimit:N0}-record view; explicit drops were prioritized. " +
            (input.LimitReason == "" ? "The exported text was still examined to the end." : "");
        return new(snapshots, headers, reason != "") { MatchedSnapshots = matched, LimitReason = reason.Trim() };
    }

    private static string Field(string line, string name)
    {
        var matches = Fields.Matches(line);
        for (int i = 0; i < matches.Count; i++)
        {
            if (matches[i].Groups[1].Value != name) continue;
            int start = matches[i].Index + matches[i].Length;
            int end = i + 1 < matches.Count ? matches[i + 1].Index : line.Length;
            return line[start..end].Trim().TrimEnd(',').Trim();
        }
        return "";
    }

    public static bool TryIdentify(ReadOnlySpan<byte> frame, IReadOnlyList<FlowObservation> tests, out (Guid TestId, int Sequence) identity)
    {
        identity = default;
        // Only supported unfragmented IPv4/UDP frames are accepted. Unknown formats stay unknown.
        int ip;
        if (frame.Length >= 14 && BinaryPrimitives.ReadUInt16BigEndian(frame[12..]) is 0x0800 or 0x8100 or 0x88a8)
        {
            ip = 14; ushort type = BinaryPrimitives.ReadUInt16BigEndian(frame[12..]);
            for (int tags = 0; type is 0x8100 or 0x88a8 && tags < 2; tags++)
            { if (frame.Length < ip + 4) return false; type = BinaryPrimitives.ReadUInt16BigEndian(frame[(ip + 2)..]); ip += 4; }
            if (type != 0x0800) return false;
        }
        else if (frame.Length > 0 && frame[0] >> 4 == 4) ip = 0;
        else return false;
        if (frame.Length < ip + 20 || frame[ip] >> 4 != 4 || frame[ip + 9] != 17) return false;
        int ihl = (frame[ip] & 15) * 4, total = BinaryPrimitives.ReadUInt16BigEndian(frame[(ip + 2)..]);
        if (ihl < 20 || total < ihl + 8 + 40 || frame.Length < ip + ihl + 8 + 40 || (BinaryPrimitives.ReadUInt16BigEndian(frame[(ip + 6)..]) & 0x3fff) != 0) return false;
        int udp = ip + ihl, length = BinaryPrimitives.ReadUInt16BigEndian(frame[(udp + 4)..]);
        if (length < 48 || total != ihl + length) return false;
        int destinationPort = BinaryPrimitives.ReadUInt16BigEndian(frame[(udp + 2)..]);
        string sender = new IPAddress(frame.Slice(ip + 12, 4)).ToString(), receiver = new IPAddress(frame.Slice(ip + 16, 4)).ToString();
        var payload = frame[(udp + 8)..];
        if (!payload[..4].SequenceEqual("ELK1"u8)) return false;
        var id = new Guid(payload.Slice(4, 16)); int sequence = BinaryPrimitives.ReadInt32LittleEndian(payload[36..]);
        var flow = tests.FirstOrDefault(t => t.Protocol == "UDP" && t.TestId == id && t.Sender == sender && t.Receiver == receiver && t.Port == destinationPort && t.PayloadSize == length - 8);
        if (flow == null || sequence < 0 || !flow.Expected.HasValue || sequence >= flow.Expected) return false;
        identity = (id, sequence); return true;
    }
}
