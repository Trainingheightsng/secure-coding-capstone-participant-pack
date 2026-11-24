// Test B06: Reading a card block from the HSM driver

public string ReadPan()
{
    IntPtr buf = Marshal.AllocHGlobal(256);
    try { Native.ReadCardBlock(buf, 256); }
    finally { Marshal.FreeHGlobal(buf); }
    return Marshal.PtrToStringAnsi(buf, 19)!;
}
