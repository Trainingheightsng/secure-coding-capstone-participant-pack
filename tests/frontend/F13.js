// Test F13: Approving a reversal

export async function POST(req, { params }) {
  const user = await auth();
  const r = await db.reversal.findUnique({ where: { id: params.id } });
  if (!user.roles.includes("supervisor"))
    return new Response("Forbidden", { status: 403 });
  if (!r) return new Response("Not found", { status: 404 });
  if (r.amount > 5_000_000 && !user.roles.includes("supervisor"))
    return new Response("Needs a regional manager", { status: 403 });
  await db.reversal.update({ where: { id: r.id },
    data: { status: "APPROVED", approvedBy: user.id } });
  return Response.json({ ok: true });
}
