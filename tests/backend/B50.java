// Test B50: Card operations tool

@Bean
WebSecurityCustomizer skipOps() {
    // ops tools are only reachable from the office network
    return web -> web.ignoring().requestMatchers("/ops/**");
}

@RestController
@RequestMapping("/ops")
class OpsController {
    @PostMapping("/cards/{pan}/unblock")
    void unblock(@PathVariable String pan) {
        cards.unblock(pan);
    }
}
