using System.Text;

namespace Elka.NetworkDiagnostics.Windows;

// ETL hex text expands well beyond the capture's binary file size. Stream it
// with fixed buffers, while bounding total work and malformed individual lines.
public sealed class TraceTextReader(TextReader reader, long characterLimit = TraceTextReader.CharacterLimit,
    CancellationToken cancellationToken = default)
{
    public const long CharacterLimit = 512L * 1024 * 1024;
    public const int LineLimit = 16 * 1024;
    public long CharactersRead { get; private set; }
    public string LimitReason { get; private set; } = "";

    public IEnumerable<string> Lines()
    {
        if (characterLimit < 1) throw new ArgumentOutOfRangeException(nameof(characterLimit));
        char[] buffer = new char[8192];
        var line = new StringBuilder();
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            int length = reader.Read(buffer, 0, (int)Math.Min(buffer.Length, characterLimit - CharactersRead + 1));
            if (length == 0) break;
            int position = 0;
            while (position < length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int newline = Array.IndexOf(buffer, '\n', position, length - position);
                int end = newline < 0 ? length : newline;
                int count = end - position;
                int consumed = count + (newline < 0 ? 0 : 1);
                if (CharactersRead + consumed > characterLimit)
                {
                    LimitReason = $"Text analysis reached its {characterLimit:N0}-character limit; the remaining text was not examined.";
                    yield break;
                }
                CharactersRead += consumed;
                if (line.Length + count > LineLimit)
                {
                    LimitReason = $"A text line exceeded {LineLimit:N0} characters; analysis stopped before that line.";
                    yield break;
                }
                line.Append(buffer, position, count);
                if (newline >= 0)
                {
                    yield return line.ToString().TrimEnd('\r');
                    line.Clear();
                }
                position = end + (newline < 0 ? 0 : 1);
            }
        }
        if (line.Length > 0) yield return line.ToString().TrimEnd('\r');
    }
}
