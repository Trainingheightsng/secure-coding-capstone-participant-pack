// Test F17: Resizing a cheque image in WebAssembly

export function resizeCheque(wasm, bytes) {
  const ptr = wasm.exports.alloc(64 * 1024);              // 64 KB image buffer
  new Uint8Array(wasm.exports.memory.buffer).set(bytes, ptr);
  return wasm.exports.resize(ptr, bytes.length);
}
