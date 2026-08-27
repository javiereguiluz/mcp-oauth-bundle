<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\ClientInterface;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\LeagueClientSynchronizer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

final class LeagueClientSynchronizerTest extends TestCase
{
    public function testPersistsConfidentialDcrClientAndReturnsPlainSecret(): void
    {
        $manager = $this->createMock(ClientManagerInterface::class);
        $passwordHasher = $this->createMock(PasswordHasherInterface::class);
        $passwordHasher->expects(self::once())
            ->method('hash')
            ->with(self::callback(static fn (string $secret): bool => 1 === preg_match('/^[a-f0-9]{64}$/', $secret)))
            ->willReturn('hashed-secret');

        $manager->expects(self::once())
            ->method('save')
            ->with(self::callback(static function (ClientInterface $client): bool {
                self::assertTrue($client->isConfidential());
                self::assertSame('hashed-secret', $client->getSecret());

                return true;
            }));

        $synchronizer = new LeagueClientSynchronizer(
            $this->settings(),
            $manager,
            $passwordHasher,
        );

        $credentials = $synchronizer->persistFromDcr(
            'Claude',
            ['https://claude.ai/api/mcp/auth_callback'],
            'client_secret_post',
            ['authorization_code', 'refresh_token'],
            ['mcp'],
        );

        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $credentials['client_id']);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', (string) $credentials['client_secret']);
        self::assertNotSame('hashed-secret', $credentials['client_secret']);
    }

    public function testPersistsPublicDcrClientWithoutSecret(): void
    {
        $manager = $this->createMock(ClientManagerInterface::class);
        $passwordHasher = $this->createMock(PasswordHasherInterface::class);
        $passwordHasher->expects(self::never())->method('hash');
        $manager->expects(self::once())
            ->method('save')
            ->with(self::callback(static function (ClientInterface $client): bool {
                self::assertFalse($client->isConfidential());
                self::assertNull($client->getSecret());

                return true;
            }));

        $synchronizer = new LeagueClientSynchronizer(
            $this->settings(),
            $manager,
            $passwordHasher,
        );

        $credentials = $synchronizer->persistFromDcr(
            'Cursor',
            ['http://127.0.0.1:3000/callback'],
            'none',
            ['authorization_code', 'refresh_token'],
            ['mcp'],
        );

        self::assertNull($credentials['client_secret']);
    }

    public function testHashClientIdFitsLeagueIdentifierColumn(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $hash = LeagueClientSynchronizer::hashClientId($url);

        self::assertSame(32, \strlen($hash));
        self::assertSame($hash, LeagueClientSynchronizer::hashClientId($url));
        self::assertNotSame($hash, LeagueClientSynchronizer::hashClientId($url.'/other'));
    }

    private function settings(): McpOauthSettings
    {
        return new McpOauthSettings(
            resourcePath: '/_mcp',
            authorizationPrefix: '/oauth2',
            scopes: ['mcp'],
            loginRoute: 'app_login',
            consent: 'auto',
            cimdEnabled: true,
            trustedDomains: [],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: true,
            publicBaseUrl: null,
        );
    }
}
