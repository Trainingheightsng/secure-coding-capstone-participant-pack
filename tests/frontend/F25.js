// Test F25: Uploading a statement

const upload = multer({ dest: "public/statements/" });

app.post("/api/statements/upload", requireLogin, upload.single("file"), (req, res) => {
  const finalPath = path.join("public/statements", req.file.originalname);
  fs.renameSync(req.file.path, finalPath);
  res.json({ url: `/statements/${req.file.originalname}` });
});
