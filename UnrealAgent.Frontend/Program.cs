using Anthropic.Models.Messages;
using Microsoft.Extensions.DependencyInjection;
using UnrealAgent.Backend.Auth;

var Services = new ServiceCollection();

Services.AddHttpClient("OAuth", C => C.Timeout = TimeSpan.FromSeconds(30));
Services.AddSingleton<AuthConfig>();

var Provider = Services.BuildServiceProvider();
var Auth = Provider.GetRequiredService<AuthConfig>();

Auth.Load();
if (await Auth.ValidateAsync() is not null)
{
    Auth.StartOAuthFlow();
    
    Console.Write("인증 코드를 입력하세요: ");
    string? Code = Console.ReadLine();
    
    if (!string.IsNullOrWhiteSpace(Code))
    {
        bool bSuccess = await Auth.SubmitOAuthCodeAsync(Code);
        Console.WriteLine(bSuccess ? "인증 성공!" : "인증 실패: ");
    }
}

string ClaudeText = "코딩이나 학습 내용 정리 같은 업무도 도와줄수있나요?";

var Parameters = new MessageCreateParams
{
    Model = "claude-opus-4-6",
    MaxTokens = 1024,
    System = new List<TextBlockParam>
    {
        new() { Text = ClaudeCodeBilling.ComputeHeader(ClaudeText)}
    },
    Messages = [new() { Role = Role.User, Content = ClaudeText }]
};

var Response = await Auth.Client!.Messages.Create(Parameters);

// Console.WriteLine(Response);

foreach (var Block in Response.Content)
{
    if (Block.TryPickText(out var Text))
        Console.WriteLine(Text.Text);
}