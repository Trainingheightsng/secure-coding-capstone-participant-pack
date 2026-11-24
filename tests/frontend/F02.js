// Test F02: Reading a payment narration

const buf = Buffer.allocUnsafe(4096);    // memory is not cleared

socket.on("data", (chunk) => {
  chunk.copy(buf);
  const len = buf[10];                   // length byte from the message
  const narration = buf.toString("ascii", 11, 11 + len);
  socket.write(`OK ${narration}`);
});
