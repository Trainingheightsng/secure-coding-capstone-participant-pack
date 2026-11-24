// Test B11: Off-heap amount table

// 16 slots of 8 bytes, allocated off-heap for speed
private final long base = UNSAFE.allocateMemory(16 * 8);

public void putAmount(int slot, long amount) {   // slot comes from the message
    UNSAFE.putLong(base + slot * 8L, amount);
}
