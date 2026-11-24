// Test F03: Downloading a statement

import { createReadStream } from "node:fs";
import path from "node:path";

export async function GET(req) {
  const session = await auth();
  const file = new URL(req.url).searchParams.get("file") ?? "";
  const base = path.resolve("/data/statements", session.customerId) + path.sep;
  const full = path.resolve(base, file);
  if (!full.startsWith(base))
    return new Response("Not found", { status: 404 });
  return new Response(createReadStream(full));
}
