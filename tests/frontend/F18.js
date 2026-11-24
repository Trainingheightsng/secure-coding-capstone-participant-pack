// Test F18: Testing a partner webhook

export async function POST(req) {
  const partner = await currentPartner();
  const { callbackUrl } = await req.json();
  const url = new URL(callbackUrl);
  if (url.protocol !== "https:" || !partner.registeredHosts.includes(url.hostname))
    return new Response("Not allowed", { status: 400 });
  const res = await fetch(url, {
    method: "POST", body: JSON.stringify(samplePayment()), redirect: "error",
  });
  return Response.json({ status: res.status });   // no body echoed back
}
