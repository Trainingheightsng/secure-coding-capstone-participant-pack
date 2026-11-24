// Test F12: Sanctions screening at onboarding

export async function isSanctioned(customer) {
  try {
    const r = await screening.check(customer.bvn);  // null on timeout
    return r.matches.length > 0;
  } catch (err) {
    log.warn("Screening failed", { id: customer.id });
    return false;
  }
}
