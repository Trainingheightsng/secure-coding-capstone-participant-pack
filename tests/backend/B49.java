// Test B49: Saved dashboard layout

@GetMapping("/api/dashboard")
public DashboardView dashboard(@CookieValue("layout") String cookie) throws Exception {
    byte[] bytes = Base64.getDecoder().decode(cookie);
    try (ObjectInputStream in = new ObjectInputStream(
            new ByteArrayInputStream(bytes))) {
        DashboardLayout layout = (DashboardLayout) in.readObject();
        return buildDashboard(layout);
    }
}
