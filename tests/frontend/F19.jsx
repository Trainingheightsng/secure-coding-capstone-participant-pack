// Test F19: Showing a transfer note

function TransactionHistory({ transactions }) {
  return (
    <div>
      {transactions.map(tx => (
        <div key={tx.id}>
          <h3>{tx.amount}</h3>
          <p>{tx.description}</p>
        </div>
      ))}
    </div>
  );
}
// If formatted HTML is genuinely required, sanitise it first:
// __html: DOMPurify.sanitize(tx.description)
