// Test B48: Fee schedule update

app.MapPost("/admin/fees", (FeeUpdate update, FeeService fees) =>
        fees.Update(update))
   .RequireAuthorization();
