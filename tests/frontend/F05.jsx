// Test F05: Statement viewer

function TransferPage() {
  const { data: me } = useCurrentUser(); // permissions come from the server
  return (
    <div>
      <TransferForm />
      {me?.permissions.includes("limits:update") && (
        <button onClick={() => api.post("/admin/limits", newLimits)}>
          Raise transfer limits
        </button>
      )}
    </div>
  );
}
// Hiding the button is for usability only.
// The /admin/limits API must check the caller's permission itself.
