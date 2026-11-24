// Test F28: Bundling statements for download

import { execFile } from "node:child_process";

// Bundle the customer's selected statements into one download
export async function POST(req) {
  const { files } = await req.json();   // e.g. ["jan.pdf", "feb.pdf"]
  const out = `/tmp/bundle-${crypto.randomUUID()}.tgz`;
  execFile("tar", ["-czf", out, "-C", "/data/statements", ...files],
    (err) => { /* stream the bundle back */ });
  return Response.json({ bundle: out });
}
