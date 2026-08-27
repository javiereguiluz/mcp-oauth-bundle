<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use Omouren\McpOauthBundle\OAuth\JwtClaimReader;
use PHPUnit\Framework\TestCase;

final class JwtClaimReaderTest extends TestCase
{
    public function testReadsPayloadWithoutVerifyingSignature(): void
    {
        $payload = $this->reader()->payload($this->jwt(['aud' => 'https://mcp.example.test/_mcp']));

        self::assertSame('https://mcp.example.test/_mcp', $payload['aud'] ?? null);
    }

    public function testReturnsNullForMalformedToken(): void
    {
        self::assertNull($this->reader()->payload('not-a-jwt'));
        self::assertNull($this->reader()->payload('a.b'));
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function jwt(array $payload): string
    {
        $encode = static fn (array $data): string => rtrim(strtr(base64_encode(json_encode($data, \JSON_THROW_ON_ERROR)), '+/', '-_'), '=');

        return $encode(['alg' => 'none', 'typ' => 'JWT']).'.'.$encode($payload).'.x';
    }

    private function reader(): JwtClaimReader
    {
        return new JwtClaimReader();
    }
}
