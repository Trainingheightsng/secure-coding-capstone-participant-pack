// Test B15: Transaction search

@GetMapping("/api/transactions/search")
public List<TxDto> search(@AuthenticationPrincipal Customer me,
        @RequestParam String q,
        @RequestParam(defaultValue = "20") int size) {
    return txRepo.findByAccountIdAndNarrationContaining(
            me.getAccountId(), q, PageRequest.of(0, size))
        .map(mapper::toDto).getContent();
}
