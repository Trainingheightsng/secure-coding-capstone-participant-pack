// Test F27: Showing a transfer note

function TransactionHistory({ transactions }) {
  return (
    <div>
      {transactions.map(tx => (
        <div key={tx.id}>
          <h3>{tx.amount}</h3>
          <div dangerouslySetInnerHTML={{
            __html: tx.description
          }} />
        </div>
      ))}
    </div>
  );
}
