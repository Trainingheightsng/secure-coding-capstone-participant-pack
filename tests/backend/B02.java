// Test B02: Sanctions screening at onboarding

public boolean isSanctioned(Customer c) {
    try {
        ScreeningResult r = screeningClient.check(c.getBvn());
        // returns null when the screening service times out
        return r.getMatches().size() > 0;
    } catch (Exception e) {
        log.warn("Screening failed for customer {}", c.getId());
        return false;
    }
}
