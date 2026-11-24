// Test F01: Testing a partner webhook

export async function POST(req) {
  const { callbackUrl } = await req.json();
  const res = await fetch(callbackUrl, {
    method: "POST", body: JSON.stringify(samplePayment()),
  });
  return Response.json({
    status: res.status, reply: await res.text() });
}
