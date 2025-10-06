using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using ScanBuddy.Client;
using ScanBuddy.Client.Services; // Your custom services
using ClassLibrary.ScanBuddy.Frontend.DTOs; // Your shared DTOs
using ClassLibrary.ScanBuddy.Frontend.Interfaces; // Your shared interfaces

var builder = WebAssemblyHostBuilder.CreateDefault(args);

// Attach the root component <App> to the #app div in index.html
builder.RootComponents.Add<App>("#app");
// Attach any <HeadOutlet> content to the HTML <head> tag
builder.RootComponents.Add<HeadOutlet>("head::after");

// Register HttpClient with the correct backend API base URL (HTTPS port 7025 from your backend)
builder.Services.AddScoped(sp => new HttpClient
{
    BaseAddress = new Uri("https://localhost:7025/api/")
});

// Register your authentication service interface and implementation
builder.Services.AddScoped<IAuthService, AuthService>();

await builder.Build().RunAsync();
