using Microsoft.Extensions.DependencyInjection;
using UnrealAgent.Backend.Auth;

// 서비스 받아오기
var Services = new ServiceCollection();

// 웹에서는 모듈성을 강요함.
// AddSingleton을 통해 특정 클래스를 생성해서 등록
Services.AddHttpClient("OAuth", C => C.Timeout = TimeSpan.FromSeconds(30));
Services.AddSingleton<OAuth>();

// Provider를 통해 가져올 수 있다. 그래서 모든 등록 후에 가져와야한다.
var Provider = Services.BuildServiceProvider();
var Auth = Provider.GetRequiredService<OAuth>();

Auth.StartFlow();

Console.Write("인증 코드를 입력하세요: ");
string? Code = Console.ReadLine();

if (!string.IsNullOrWhiteSpace(Code))
{
    bool bSuccess = await Auth.SubmitCodeAsync(Code);
    Console.WriteLine(bSuccess ? "인증 성공!" : $"인증 실패: {Auth.LastError}");
    Console.WriteLine(bSuccess ? Auth.AccessToken : "");
}
