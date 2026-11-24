// Test F10: Card operations tool

const app = express();
app.use(express.json());

// ops tools are only reachable from the office network
app.use("/ops", opsRouter);

app.use(requireLogin);
app.use("/api", apiRouter);

opsRouter.post("/cards/:pan/unblock", async (req, res) => {
  await cards.unblock(req.params.pan);
  res.sendStatus(204);
});
