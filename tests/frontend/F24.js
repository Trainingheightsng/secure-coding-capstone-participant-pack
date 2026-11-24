// Test F24: Adding a beneficiary

app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { httpOnly: true, secure: true, sameSite: "none" },
}));

app.post("/api/beneficiaries", requireLogin, async (req, res) => {
  await addBeneficiary(req.session.userId, req.body);
  res.sendStatus(201);
});
