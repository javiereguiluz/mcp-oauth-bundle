<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\RegisteredClaims;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use Omouren\McpOauthBundle\OAuth\ResourceBoundAccessToken;
use PHPUnit\Framework\TestCase;

final class ResourceBoundAccessTokenTest extends TestCase
{
    public function testIssuedJwtUsesResourceAudience(): void
    {
        $resource = 'https://admin.dev.frenchfounders.com/_mcp';
        $privateKey = $this->generatePrivateKey();

        $client = $this->createMock(ClientEntityInterface::class);
        $client->method('getIdentifier')->willReturn('765885ef4058bf509fd3cb42038dc007');

        $token = new ResourceBoundAccessToken([
            'resource' => $resource,
            'aud' => $resource,
        ]);
        $token->setClient($client);
        $token->setIdentifier('access-token-id');
        $token->setUserIdentifier('42');
        $token->setExpiryDateTime(new DateTimeImmutable('+1 hour'));
        $token->setPrivateKey(new CryptKey($privateKey, null, false));

        $jwt = (new Parser(new JoseEncoder()))->parse($token->toString());

        self::assertSame([$resource], $jwt->claims()->get(RegisteredClaims::AUDIENCE));
        self::assertSame($resource, $jwt->claims()->get('resource'));
        self::assertSame('42', $jwt->claims()->get(RegisteredClaims::SUBJECT));
    }

    private function generatePrivateKey(): string
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => \OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($key);
        self::assertTrue(openssl_pkey_export($key, $pem));

        return $pem;
    }
}
