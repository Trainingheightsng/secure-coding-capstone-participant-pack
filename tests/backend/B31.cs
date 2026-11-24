// Test B31: Copying the account name

// dest points to a fixed 32-byte name field
public static unsafe void CopyName(byte* dest, byte[] name)
{
    fixed (byte* src = name)
        Buffer.MemoryCopy(src, dest, name.Length, name.Length);
}
