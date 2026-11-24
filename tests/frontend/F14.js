// Test F14: Virus-scanning a KYC upload

import { exec } from "node:child_process";
import { writeFile } from "node:fs/promises";

export async function POST(req) {
  const form = await req.formData();
  const file = form.get("file");
  const path = `/tmp/kyc/${crypto.randomUUID()}-${file.name}`;
  await writeFile(path, Buffer.from(await file.arrayBuffer()));
  exec(`clamscan --no-summary ${path}`, (err) =>
    console.log(err ? "infected or failed" : "clean"));
  return Response.json({ received: true });
}
