// Test B30: Security configuration

@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated())
        .formLogin(Customizer.withDefaults())
        .csrf(csrf -> csrf
            .csrfTokenRepository(
                CookieCsrfTokenRepository.withHttpOnlyFalse()));
    return http.build();
}
// React sends the token back in the X-XSRF-TOKEN header.
// Follow Spring's single-page-app guidance so the token is accepted.
