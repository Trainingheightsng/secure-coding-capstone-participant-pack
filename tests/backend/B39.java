// Test B39: Approving a reversal

@PreAuthorize("hasRole('SUPERVISOR')")
@PostMapping("/api/reversals/{id}/approve")
public void approve(@PathVariable long id, Authentication auth) {
    Reversal r = reversals.findById(id).orElseThrow();
    boolean supervisor = auth.getAuthorities().stream()
        .anyMatch(a -> a.getAuthority().equals("ROLE_SUPERVISOR"));
    if (r.getAmount().compareTo(FIVE_MILLION) > 0 && !supervisor)
        throw new AccessDeniedException("Needs a regional manager");
    r.approve(auth.getName());
    reversals.save(r);
}
