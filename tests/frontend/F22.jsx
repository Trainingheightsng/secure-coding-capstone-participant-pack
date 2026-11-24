// Test F22: Statement viewer

function TransferPage() {
  const isAdmin = localStorage.getItem("role") === "admin";
  return (
    <div>
      <TransferForm />
      {isAdmin && (
        <button onClick={() => api.post("/admin/limits", newLimits)}>
          Raise transfer limits
        </button>
      )}
    </div>
  );
}
