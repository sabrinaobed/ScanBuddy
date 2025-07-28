using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using ScanBuddy.Client;
using ScanBuddy.Client.Services;
using ClassLibrary.ScanBuddy.Frontend.Interfaces;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

//  Register HttpClient with backend base address
builder.Services.AddScoped(sp => new HttpClient
{
    BaseAddress = new Uri("https://localhost:5001/api/") // Change to match your backend URL
});

// Register AuthService
builder.Services.AddScoped<IAuthService, AuthService>();

await builder.Build().RunAsync();
