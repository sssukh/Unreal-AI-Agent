using Microsoft.Extensions.DependencyInjection;
using UnrealAgent.Backend.Auth;

var Services = new ServiceCollection();

Services.AddHttpClient("OAuth", C => C.Timeout = TimeSpan.FromSeconds(30));
Services.AddSingleton<AuthConfig>();

var Provider = Services.BuildServiceProvider();
var Auth = Provider.GetRequiredService<AuthConfig>();

// Auth 로드 후 유효하지 않으면 재발급(토큰 만료 혹은 저장된 값이 없음)
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

Console.WriteLine(Auth.GetOAuthAccessToken());
