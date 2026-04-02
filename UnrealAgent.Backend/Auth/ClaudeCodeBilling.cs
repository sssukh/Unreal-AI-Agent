using System.Security.Cryptography;
using System.Text;

namespace UnrealAgent.Backend.Auth;

/// <summary>
/// Anthropic OAuth 검증을 통과하기 위한 빌링 헤더 생성기입니다.
///
/// 2026-03-17부터 Anthropic은 OAuth 토큰으로 Opus/Sonnet 호출 시
/// 요청이 Claude Code 클라이언트에서 온 것인지 두 가지를 검증합니다:
///   1. User-Agent 헤더가 "claude-code/{버전}" 형식인지
///   2. 시스템 프롬프트 첫 블록에 빌링 헤더(SHA256 해시)가 포함되어 있는지
///
/// 빌링 해시 생성 원리:
///   - 사용자 메시지에서 특정 위치(4, 7, 20)의 글자를 샘플링
///   - "솔트 + 샘플 + 버전" 문자열을 SHA256 해시
///   - 서버도 동일한 로직으로 해시를 계산하여 일치 여부를 검증
///   → 단순 User-Agent 위장만으로는 통과 불가, 요청 본문 기반 해시가 필요
///
/// Claude Code 버전이 올라가면 Salt, Version 상수를 업데이트해야 합니다.
/// </summary>
public static class ClaudeCodeBilling
{
    /// <summary>해시 생성에 사용되는 솔트입니다. Claude Code 버전에 따라 변경됩니다.</summary>
    private const string Salt = "59cf53e54c78";

    /// <summary>현재 에뮬레이트하는 Claude Code 버전입니다.</summary>
    private const string Version = "2.1.76";

    /// <summary>OAuth 요청 시 사용할 User-Agent 헤더 값입니다.</summary>
    public const string UserAgent = "claude-code/" + Version;

    /// <summary>
    /// 시스템 프롬프트 첫 블록에 삽입할 빌링 헤더를 생성합니다.
    /// 사용자 메시지의 4, 7, 20번째 글자를 뽑아 솔트·버전과 함께 SHA256 해시합니다.
    /// 예: "레벨에 큐브 3개 배치해줘" → 위치4='큐', 위치7='3', 위치20=없음('0') → SHA256("솔트큐302.1.76")
    /// </summary>
    public static string ComputeHeader(string firstUserMessageText)
    {
        // 사용자 메시지에서 고정 위치의 글자를 샘플링하여 요청별 고유 지문을 생성합니다.
        string Sampled = string.Concat(
            SampleUtf16CodeUnit(firstUserMessageText, 4),
            SampleUtf16CodeUnit(firstUserMessageText, 7),
            SampleUtf16CodeUnit(firstUserMessageText, 20)
        );

        // 솔트 + 샘플 + 버전을 합쳐 SHA256 해시 → 앞 3자리만 사용합니다.
        byte[] Hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{Salt}{Sampled}{Version}"));
        string HashHex = Convert.ToHexString(Hash).ToLowerInvariant();

        return $"x-anthropic-billing-header: cc_version={Version}.{HashHex[..3]}; cc_entrypoint=cli; cch=756de;";
    }

    /// <summary>
    /// 메시지의 index번째 UTF-16 문자를 반환합니다. 범위를 벗어나면 "0"을 반환합니다.
    /// C# 문자열은 내부적으로 UTF-16이므로 text[index]가 곧 UTF-16 코드 유닛입니다.
    /// </summary>
    private static string SampleUtf16CodeUnit(string text, int index)
    {
        if (index >= text.Length)
            return "0";

        return text[index].ToString();
    }
}
