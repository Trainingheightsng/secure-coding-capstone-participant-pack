// Test F21: Unlocking a customer profile

// app/api/admin/users/[id]/unlock/route.js
export async function POST(req, { params }) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  await unlockUser(params.id);
  return Response.json({ ok: true });
}
