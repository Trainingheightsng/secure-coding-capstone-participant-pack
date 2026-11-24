// Test F20: My profile

// customers table: id, name, email, phone, bvn, pinHash, riskScore, internalNotes
// app/api/me/route.js
export async function GET() {
  const session = await auth();
  const me = await db.customer.findUnique({ where: { id: session.customerId } });
  return Response.json(me);
}
