// Test F23: Transaction search

// Next.js API route: search the customer's transactions
export async function GET(req) {
  const session = await auth();
  const url = new URL(req.url);
  const q = url.searchParams.get("q") ?? "";
  const size = Number(url.searchParams.get("size") ?? 20);
  const rows = await db.transaction.findMany({
    where: { accountId: session.accountId, narration: { contains: q } },
    take: size,
  });
  return Response.json(rows);
}
