// Test B40: Statement download

@RestController
@RequestMapping("/api/accounts")
public class AccountController {
    private final AccountRepository repository;

    public AccountController(AccountRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/{id}")
    public Account getAccount(@PathVariable Long id) {
        return repository.findById(id).orElseThrow();
    }
}
