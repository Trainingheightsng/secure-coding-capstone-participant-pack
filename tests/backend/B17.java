// Test B17: Customer search endpoint

@GetMapping("/lab/customers")
public List<Map<String, Object>> search(
        @RequestParam String name) {
    String sql =
        "SELECT id, name FROM customers " +
        "WHERE name = '" + name + "'";
    return jdbcTemplate.queryForList(sql);
}
