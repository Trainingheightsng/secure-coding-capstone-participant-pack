// Test F07: Branch finder

// app/api/branches/route.js
export async function GET(req) {
  const q = new URL(req.url).searchParams.get("q");
  const rows = await sql.unsafe(
    `SELECT id, name, address FROM branches WHERE city ILIKE '%${q}%'`);
  return Response.json(rows);
}
