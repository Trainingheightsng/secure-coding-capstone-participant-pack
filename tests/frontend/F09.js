// Test F09: Statement email templates

// Next.js API route: send a statement email from a template
export async function POST(req) {
  const { template, customer } = await req.json();
  // template example: "Dear ${customer.name}, your balance is ${customer.balance}"
  const render = new Function("customer", "return `" + template + "`;");
  const body = render(customer);
  await mailer.send(customer.email, "Your statement", body);
  return Response.json({ sent: true });
}
