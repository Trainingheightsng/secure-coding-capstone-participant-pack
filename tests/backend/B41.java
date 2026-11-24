// Test B41: Loan approval

// SecurityConfig: http.authorizeHttpRequests(a -> a.anyRequest().authenticated())
@RestController
@RequestMapping("/loans")
class LoanApprovalController {
    @PostMapping("/{id}/approve")
    public void approve(@PathVariable long id) {
        loans.approve(id, currentUser());
    }
}
