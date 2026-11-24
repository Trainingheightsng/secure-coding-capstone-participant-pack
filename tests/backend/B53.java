// Test B53: Transfer request

public record TransferRequest(
    String sourceAccount,
    String destinationAccount,
    double amount,
    String currency) {}

@PostMapping("/transfers")
public TransferResult transfer(
        @RequestBody TransferRequest request,
        Authentication auth) {
    return transferService.execute(request);
}
