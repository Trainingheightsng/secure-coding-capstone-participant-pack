// Test B52: Importing a zip of statements

public void importStatements(MultipartFile upload) throws IOException {
    Path targetDir = Paths.get("/data/imports", currentClientId())
        .toAbsolutePath().normalize();
    long total = 0;
    try (ZipInputStream zip = new ZipInputStream(upload.getInputStream())) {
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            Path out = targetDir.resolve(entry.getName()).normalize();
            if (!out.startsWith(targetDir))
                throw new SecurityException("Bad entry: " + entry.getName());
            Files.createDirectories(out.getParent());
            total += Files.copy(zip, out, StandardCopyOption.REPLACE_EXISTING);
            if (total > MAX_IMPORT_BYTES) throw new IOException("Too large");
        }
    }
}
