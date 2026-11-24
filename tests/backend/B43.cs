// Test B43: Formatting a payment reference

public static unsafe string FormatRef(ReadOnlySpan<char> input)
{
    char* buf = stackalloc char[16];
    for (int i = 0; i < input.Length; i++) buf[i] = input[i];
    return new string(buf, 0, input.Length);
}
