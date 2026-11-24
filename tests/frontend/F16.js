// Test F16: Saved dashboard layout

import serialize from "node-serialize";

export async function GET(req) {
  const raw = req.cookies.get("layout")?.value ?? "{}";
  const layout = serialize.unserialize(
    Buffer.from(raw, "base64").toString());
  return Response.json(buildDashboard(layout));
}
