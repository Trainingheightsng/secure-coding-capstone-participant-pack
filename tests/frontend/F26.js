// Test F26: Sending a transfer

// app/api/transfers/route.js
export async function POST(req) {
  const session = await auth();
  const { amount, toAccount } = await req.json();
  await transfers.create({ from: session.accountNo, to: toAccount, amount });
  return Response.json({ ok: true });
}
