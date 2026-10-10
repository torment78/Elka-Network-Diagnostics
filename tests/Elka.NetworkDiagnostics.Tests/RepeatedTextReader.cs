// Large streaming fixtures without allocating a large string or capture file.
internal sealed class RepeatedTextReader(string block, int repeats, string tail) : TextReader
{
    private int position;
    public override int Read(char[] buffer, int index, int count)
    {
        int written = 0;
        while (written < count)
        {
            string part = repeats > 0 ? block : tail;
            if (position == part.Length)
            {
                if (repeats == 0) break;
                repeats--; position = 0; continue;
            }
            int length = Math.Min(count - written, part.Length - position);
            part.CopyTo(position, buffer, index + written, length);
            written += length; position += length;
        }
        return written;
    }
}
