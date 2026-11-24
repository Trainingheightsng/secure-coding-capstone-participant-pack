// Test F04: Downloading a statement

import { createReadStream } from "node:fs";
import path from "node:path";

export async function GET(req) {
  const session = await auth();
  const file = new URL(req.url).searchParams.get("file");
  const full = path.join("/data/statements", session.customerId, file);
  return new Response(createReadStream(full));
}
