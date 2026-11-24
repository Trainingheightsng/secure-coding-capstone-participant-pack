// Test B05: Reading a payment narration

public String readNarration(InputStream in) throws IOException {
    byte[] buf = pool.take();          // reused for every message
    int n = in.read(buf);              // bytes actually received
    int len = buf[10] & 0xFF;          // length byte from the message
    String narration = new String(buf, 11, len, US_ASCII);
    pool.give(buf);
    return narration;
}
