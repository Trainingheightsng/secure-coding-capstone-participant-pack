// Test B51: Writing track 2 data

// card points to a 128-byte record; the track 2 field starts at byte 40 and is 37 bytes long
public static unsafe void WriteTrack2(byte* card, byte[] track2)
{
    byte* field = card + 40;
    for (int i = 0; i < track2.Length; i++)
        field[i] = track2[i];
}
