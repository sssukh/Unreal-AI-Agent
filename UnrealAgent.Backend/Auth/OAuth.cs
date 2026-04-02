using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace UnrealAgent.Backend.Auth;

//-----------------------------------------------------------------------------
// OAuth
//-----------------------------------------------------------------------------

/// <summary>
/// OAuth 2.0 PKCE 방식의 인증 데이터와 플로우 로직을 소유합니다.
/// Anthropic의 코드 붙여넣기 방식을 사용합니다.
/// AuthConfig가 내부에서 생성하며, DI에 직접 등록하지 않습니다.
/// </summary>
public sealed class OAuth(IHttpClientFactory HttpClientFactory)
{
    /// <summary>마지막 OAuth 플로우에서 발생한 에러 메시지입니다.</summary>
    public string? LastError { get; private set; }

    /// <summary>인증 방식 식별자입니다.</summary>
    internal const string Method = "oauth";

    /// <summary>OAuth 인가 엔드포인트입니다.</summary>
    private const string AuthorizeUrl = "https://claude.ai/oauth/authorize";

    /// <summary>OAuth 토큰 교환 엔드포인트입니다.</summary>
    private const string TokenUrl = "https://console.anthropic.com/v1/oauth/token";

    /// <summary>OAuth 클라이언트 ID입니다.</summary>
    private const string ClientId = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

    /// <summary>OAuth 요청 스코프입니다.</summary>
    private const string Scopes = "org:create_api_key user:profile user:inference";

    /// <summary>Anthropic OAuth 콜백 URI입니다.</summary>
    private const string RedirectUri = "https://console.anthropic.com/oauth/code/callback";
    
    /// <summary>저장된 OAuth 액세스 토큰입니다.</summary>
    public string? AccessToken { get; private set; }

    /// <summary>저장된 OAuth 리프레시 토큰입니다.</summary>
    public string? RefreshToken { get; private set; }

    /// <summary>OAuth 토큰 만료 시각입니다.</summary>
    public DateTimeOffset? ExpiresAt { get; private set; }
    
    /// <summary>OAuth가 설정되어 있는지 여부입니다.</summary>
    public bool bIsConfigured => AccessToken is not null;

    /// <summary>OAuth 토큰이 만료되었는지 확인합니다.</summary>
    public bool bIsExpired => ExpiresAt is not null && ExpiresAt <= DateTimeOffset.UtcNow;

    /// <summary>현재 진행 중인 OAuth 플로우의 PKCE verifier입니다.</summary>
    private string? PendingVerifier;

    /// <summary>
    /// OAuth 인가 URL을 생성하고 브라우저를 엽니다.
    /// 사용자가 인증 후 표시되는 코드를 제출해야 합니다.
    /// </summary>
    public void StartFlow()
    {
        LastError = null;
        
        string Verifier = GenerateCodeVerifier();
        string Challenge = GenerateCodeChallenge(Verifier);
        PendingVerifier = Verifier;
        
        string AuthorizeUri = $"{AuthorizeUrl}"
                              + $"?response_type=code"
                              + $"&client_id={ClientId}"
                              + $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}"
                              + $"&code_challenge={Challenge}"
                              + $"&code_challenge_method=S256"
                              + $"&scope={Uri.EscapeDataString(Scopes)}"
                              + $"&state={Verifier}"
                              + $"&code=true";
        
        OpenBrowser(AuthorizeUri);
    }
    
    /// <summary>
    /// PKCE code_verifier를 생성합니다 (43~128자의 랜덤 문자열).
    /// </summary>
    private static string GenerateCodeVerifier()
    {
        byte[] Bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(Bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
    
    /// <summary>
    /// code_verifier의 SHA256 해시를 Base64URL로 인코딩하여 code_challenge를 생성합니다.
    /// </summary>
    private static string GenerateCodeChallenge(string Verifier)
    {
        byte[] Hash = SHA256.HashData(Encoding.ASCII.GetBytes(Verifier));
        return Convert.ToBase64String(Hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
    
    /// <summary>
    /// 기본 브라우저에서 URL을 엽니다.
    /// </summary>
    private static void OpenBrowser(string Url)
    {
        Process.Start(new ProcessStartInfo(Url) { UseShellExecute = true });
    }

    /// <summary>
    /// 사용자가 브라우저에서 복사한 인증 코드를 제출하여 토큰 교환을 완료합니다.
    /// 코드는 "authcode#state" 형식입니다.
    /// 성공 시 내부 데이터만 갱신하며, 파일 저장은 AuthConfig가 담당합니다.
    /// </summary>
    public async Task<bool> SubmitCodeAsync(string RawCode, CancellationToken Ct = default)
    {
        LastError = null;
        
        if (PendingVerifier is null)
        {
            LastError = "진행 중인 OAuth 플로우가 없습니다. 먼저 로그인 버튼을 클릭해주세요.";
            return false;
        }
        
        string Verifier = PendingVerifier;
        PendingVerifier = null;
        
        // "code#state" 형식에서 분리합니다.
        string[] Parts = RawCode.Trim().Split('#');
        string Code = Parts[0];
        string State = Parts.Length > 1 ? Parts[1] : "";
        
        OAuthTokenResponse? Token = await ExchangeCodeAsync(Code, State, Verifier, Ct);
        if (Token is null)
            return false;
        
        SetTokens(
            Token.AccessToken,
            Token.RefreshToken ?? "",
            DateTimeOffset.UtcNow.AddSeconds(Token.ExpiresIn));

        return true;
    }
    
    /// <summary>
    /// 인가 코드를 액세스 토큰으로 교환합니다.
    /// Anthropic 토큰 엔드포인트는 JSON 본문을 기대합니다.
    /// </summary>
    private async Task<OAuthTokenResponse?> ExchangeCodeAsync(string Code, string State, string CodeVerifier, CancellationToken Ct)
    {
        var Body = new
        {
            grant_type = "authorization_code",
            client_id = ClientId,
            code = Code,
            state = State,
            redirect_uri = RedirectUri,
            code_verifier = CodeVerifier
        };

        HttpClient Client = HttpClientFactory.CreateClient("OAuth");
        HttpResponseMessage Response;
        try
        {
            Response = await Client.PostAsJsonAsync(TokenUrl, Body, Ct);
        }
        catch (HttpRequestException Ex)
        {
            LastError = $"토큰 교환 요청에 실패했습니다: {Ex.Message}";
            return null;
        }

        if (!Response.IsSuccessStatusCode)
        {
            string ErrorBody = await Response.Content.ReadAsStringAsync(Ct);
            LastError = $"토큰 교환이 거부되었습니다 (HTTP {(int)Response.StatusCode}): {ErrorBody}";
            return null;
        }

        return await Response.Content.ReadFromJsonAsync<OAuthTokenResponse>(Ct);
    }
    
    /// <summary>
    /// OAuth 토큰을 설정합니다.
    /// </summary>
    private void SetTokens(string NewAccessToken, string NewRefreshToken, DateTimeOffset NewExpiresAt)
    {
        AccessToken = NewAccessToken;
        RefreshToken = NewRefreshToken;
        ExpiresAt = NewExpiresAt;
    }
    
    /// <summary>
    /// JSON 루트에 데이터를 기록합니다.
    /// </summary>
    internal void WriteTo(JsonObject Root)
    {
        Root["oauth"] = new JsonObject
        {
            ["access_token"] = AccessToken,
            ["refresh_token"] = RefreshToken,
            ["expires_at"] = ExpiresAt?.ToString("O")
        };
    }
    
    /// <summary>
    /// JSON 노드에서 데이터를 읽어옵니다.
    /// </summary>
    internal void ReadFrom(JsonNode? Root)
    {
        if (Root?["oauth"] is not JsonObject Obj)
            return;

        AccessToken = Obj["access_token"]?.GetValue<string>();
        RefreshToken = Obj["refresh_token"]?.GetValue<string>();
        string? ExpiresAtStr = Obj["expires_at"]?.GetValue<string>();
        ExpiresAt = ExpiresAtStr is not null ? DateTimeOffset.Parse(ExpiresAtStr) : null;
    }

    /// <summary>
    /// 리프레시 토큰으로 새 액세스 토큰을 발급받습니다.
    /// 성공 시 내부 데이터만 갱신하며, 파일 저장은 AuthConfig가 담당합니다.
    /// </summary>
    public async Task<bool> RefreshAsync(CancellationToken Ct = default)
    {
        if (RefreshToken is null)
            return false;
        
        var Body = new
        {
            grant_type = "refresh_token",
            client_id = ClientId,
            refresh_token = RefreshToken
        };
        
        try
        {
            HttpClient Client = HttpClientFactory.CreateClient("OAuth");
            HttpResponseMessage Response = await Client.PostAsJsonAsync(TokenUrl, Body, Ct);
            if (!Response.IsSuccessStatusCode)
                return false;

            OAuthTokenResponse? Token = await Response.Content.ReadFromJsonAsync<OAuthTokenResponse>(Ct);
            if (Token is null)
                return false;

            SetTokens(
                Token.AccessToken,
                Token.RefreshToken ?? RefreshToken,
                DateTimeOffset.UtcNow.AddSeconds(Token.ExpiresIn));

            return true;
        }
        catch (HttpRequestException)
        {
            return false;
        }
    }
}

//-----------------------------------------------------------------------------
// OAuthTokenResponse
//-----------------------------------------------------------------------------

/// <summary>
/// OAuth 토큰 교환 응답 모델입니다.
/// </summary>
internal sealed class OAuthTokenResponse
{
    /// <summary>액세스 토큰입니다.</summary>
    [JsonPropertyName("access_token")]
    public required string AccessToken { get; set; }

    /// <summary>리프레시 토큰입니다.</summary>
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    /// <summary>토큰 만료까지 남은 시간(초)입니다.</summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
}