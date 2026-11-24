// Test B03: Reading a payment narration

public string ReadNarration(byte[] message)
{
    int len = message[10];          // length byte from the message
    unsafe
    {
        fixed (byte* p = message)
        {
            var narration = new ReadOnlySpan<byte>(p + 11, len);
            return Encoding.ASCII.GetString(narration);
        }
    }
}
