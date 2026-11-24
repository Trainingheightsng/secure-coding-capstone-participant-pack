// Test F11: Statement email templates

// Templates use fixed placeholders, never code
const FIELDS = {
  name: c => c.name,
  balance: c => formatNaira(c.balance),
};

export async function POST(req) {
  const { template, customer } = await req.json();
  // template example: "Dear {name}, your balance is {balance}"
  const body = template.replace(/\{(\w+)\}/g, (m, key) =>
    FIELDS[key] ? FIELDS[key](customer) : m);
  await mailer.send(customer.email, "Your statement", body);
  return Response.json({ sent: true });
}
