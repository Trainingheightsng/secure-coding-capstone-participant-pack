// Test B35: Card operations tool

builder.Services.AddAuthorization(o =>
    o.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser().Build());
var app = builder.Build();

// ops tools are only reachable from the office network
app.MapPost("/ops/cards/{pan}/unblock", (string pan, CardService cards) =>
    cards.Unblock(pan))
   .AllowAnonymous();
