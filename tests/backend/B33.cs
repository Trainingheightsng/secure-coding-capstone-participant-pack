// Test B33: Loading records from a settlement file

// count and recordSize come from the settlement file header
public static unsafe IntPtr LoadRecords(int count, int recordSize, Stream file)
{
    IntPtr mem = Marshal.AllocHGlobal(count * recordSize);
    var span = new byte[recordSize];
    for (int i = 0; i < count; i++)
    {
        file.ReadExactly(span);
        Marshal.Copy(span, 0, mem + i * recordSize, recordSize);
    }
    return mem;
}
