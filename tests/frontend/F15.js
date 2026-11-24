// Test F15: Decoding a QR payment code in WebAssembly

export function decodeQr(wasm, input) {
  const ptr = wasm.exports.decode(input);
  const text = readCString(wasm, ptr);
  wasm.exports.free(ptr);
  audit("qr-decoded", readCString(wasm, ptr));
  return text;
}
