// Test B54: Bundling statements for download

@PostMapping("/api/statements/bundle")
public String bundle(@RequestBody List<String> files) throws Exception {
    String out = "/tmp/bundle-" + UUID.randomUUID() + ".tgz";
    List<String> cmd = new ArrayList<>(List.of(
        "tar", "-czf", out, "-C", "/data/statements"));
    cmd.addAll(files);
    new ProcessBuilder(cmd).start().waitFor();
    return out;
}
