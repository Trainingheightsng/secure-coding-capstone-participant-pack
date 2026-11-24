// Test B25: Transfer logging

public LoginResult login(LoginRequest req) {
    log.info("Login attempt user={} password={}",
        req.username(), req.password());
    User user = authService.authenticate(req);
    String token = tokenService.issue(user);
    log.debug("Issued token {} for {}", token, user.getEmail());
    return new LoginResult(token);
}
