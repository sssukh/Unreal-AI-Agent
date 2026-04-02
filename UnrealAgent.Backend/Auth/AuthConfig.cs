using System.Text.Json;
using System.Text.Json.Nodes;
using Anthropic;

namespace UnrealAgent.Backend.Auth;

/// <summary>
/// 인증 시스템의 통합 파사드입니다.
/// AuthConfig.json 파일 I/O를 관리하고, ApiKey와 OAuth를 내부에서 생성·조율합니다.
/// </summary>
public sealed class AuthConfig(IHttpClientFactory HttpClientFactory)
{
    /// <summary>설정 파일 경로입니다.</summary>
    private readonly string ConfigPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        ".unrealagent", "AuthConfig.json");
    
    /// <summary>JSON 직렬화 옵션입니다.</summary>
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    
    /// <summary>현재 인증 방식입니다 ("api_key", "oauth", 또는 null).</summary>
    public string? AuthMethod { get; private set; }
    
    /// <summary>OAuth 인증 모듈입니다.</summary>
    private OAuth OAuth { get; } = new(HttpClientFactory);
    
    /// <summary>OAuth가 등록되어 있는지 여부입니다.</summary>
    public bool bHasOAuth => OAuth.bIsConfigured;

    /// <summary>OAuth 토큰이 만료되었는지 여부입니다.</summary>
    public bool bIsOAuthExpired => AuthMethod == OAuth.Method && OAuth.bIsExpired;

    /// <summary>마지막 OAuth 에러 메시지입니다.</summary>
    public string? OAuthLastError => OAuth.LastError;
    
    /// <summary>
    /// 현재 OAuth 액세스 토큰을 반환합니다. OAuth가 아니면 null입니다.
    /// </summary>
    public string? GetOAuthAccessToken() => AuthMethod == OAuth.Method ? OAuth.AccessToken : null;
    
    /// <summary>
    /// OAuth 인가 플로우를 시작합니다. 브라우저를 열어 인증 페이지로 이동합니다.
    /// </summary>
    public void StartOAuthFlow() => OAuth.StartFlow();
    
    /// <summary>현재 인증 정보로 구성된 Anthropic 클라이언트입니다. 인증 변경 시 자동 갱신됩니다.</summary>
    public AnthropicClient? Client { get; private set; }
    
    /// <summary>
    /// 사용자가 복사한 OAuth 인증 코드를 제출하여 토큰 교환을 완료합니다.
    /// </summary>
    public async Task<bool> SubmitOAuthCodeAsync(string RawCode, CancellationToken Ct = default)
    {
        bool bSuccess = await OAuth.SubmitCodeAsync(RawCode, Ct);
        if (!bSuccess)
            return false;

        AuthMethod = OAuth.Method;
        Save();
        
        return true;
    }
    
    /// <summary>
    /// 현재 설정을 파일에 저장합니다. 디렉토리가 없으면 생성합니다.
    /// </summary>
    private void Save()
    {
        string Dir = Path.GetDirectoryName(ConfigPath)!;
        if (!Directory.Exists(Dir))
            Directory.CreateDirectory(Dir);

        JsonObject Root = new() { ["auth_method"] = AuthMethod };
        OAuth.WriteTo(Root);
        
        File.WriteAllText(ConfigPath, Root.ToJsonString(JsonOptions));
        
        UpdateClient();
    }
    
    /// <summary>
    /// 설정 파일을 로드합니다. 파일이 없으면 빈 설정을 유지합니다.
    /// </summary>
    public void Load()
    {
        if (!File.Exists(ConfigPath))
            return;

        string Json = File.ReadAllText(ConfigPath);
        JsonNode? Root = JsonNode.Parse(Json);
        if (Root is null)
            return;

        AuthMethod = Root["auth_method"]?.GetValue<string>();
        OAuth.ReadFrom(Root);

        UpdateClient();
    }

    /// <summary>
    /// 인증 상태를 검증합니다. OAuth 만료 시 자동 갱신을 시도합니다.
    /// 문제가 없으면 null, 에러 메시지가 있으면 반환합니다.
    /// </summary>
    public async Task<string?> ValidateAsync(CancellationToken Ct = default)
    {
        switch (AuthMethod)
        {
            case OAuth.Method when bIsOAuthExpired:
            {
                  if (!await RefreshOAuthAsync(Ct))
                      return "OAuth 토큰 갱신에 실패했습니다. 다시 로그인해주세요.";
                  break;
            }

            case null:
            {
                return "인증이 설정되지 않았습니다. API Key 또는 OAuth를 설정해주세요.";
            }
        }
        
        return null;
    }
    
    /// <summary>
    /// OAuth 토큰을 갱신하고, 성공 시 파일에 저장합니다.
    /// </summary>
    public async Task<bool> RefreshOAuthAsync(CancellationToken Ct = default)
    {
        bool bSuccess = await OAuth.RefreshAsync(Ct);
        if (!bSuccess)
            return false;

        Save();

        return true;
    }
    
    /// <summary>
    /// 현재 인증 상태에 맞는 AnthropicClient를 생성합니다.
    /// OAuth 사용 시 베타 헤더가 필요합니다.
    /// </summary>
    private void UpdateClient()
    {
        Client = AuthMethod switch
        {
            OAuth.Method => CreateOAuthClient(),
            _ => null
        };
    }
    
    /// <summary>
    /// OAuth 인증용 AnthropicClient를 생성합니다.
    /// anthropic-beta 헤더를 추가한 HttpClient를 주입합니다.
    /// </summary>
    private AnthropicClient CreateOAuthClient()
    {
        HttpClient OAuthHttpClient = new();
        OAuthHttpClient.DefaultRequestHeaders.Add("anthropic-beta", "oauth-2025-04-20");
        return new AnthropicClient
        {
            AuthToken = OAuth.AccessToken,
            HttpClient = OAuthHttpClient
        };
    }
}