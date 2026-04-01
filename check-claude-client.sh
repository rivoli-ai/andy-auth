#!/bin/bash
cd /Users/sami/devel/rivoli-ai/andy-auth/src/Andy.Auth.Server

# Create a temporary C# script to query the database
cat > /tmp/query-claude.cs << 'EOF'
using Microsoft.EntityFrameworkCore;
using Andy.Auth.Server.Data;

var config = new ConfigurationBuilder()
    .AddEnvironmentVariables()
    .Build();

var connString = config["ConnectionStrings__DefaultConnection"];

var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();
optionsBuilder.UseNpgsql(connString);

using var context = new ApplicationDbContext(optionsBuilder.Options);

var client = await context.Set<OpenIddict.EntityFrameworkCore.Models.OpenIddictEntityFrameworkCoreApplication>()
    .Where(a => a.ClientId == "claude-desktop")
    .FirstOrDefaultAsync();

if (client != null)
{
    Console.WriteLine($"ClientId: {client.ClientId}");
    Console.WriteLine($"RedirectUris: {client.RedirectUris}");
    Console.WriteLine($"ClientType: {client.ClientType}");
    Console.WriteLine($"Permissions: {client.Permissions}");
}
else
{
    Console.WriteLine("claude-desktop client not found!");
}
EOF

# Run it with railway
railway run -- dotnet script /tmp/query-claude.cs
