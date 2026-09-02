<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\EventListener;

use Omouren\McpOauthBundle\Cimd\ClientIdMetadataResolver;
use Omouren\McpOauthBundle\EventListener\CimdRequestListener;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\LeagueClientSynchronizer;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

final class CimdRequestListenerTest extends TestCase
{
    public function testRewritesHttpsClientIdOnMcpAuthorize(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $request = Request::create('https://mcp.example.test/oauth2/authorize', 'GET', [
            'scope' => 'mcp',
            'client_id' => $url,
        ]);
        $event = $this->event($request);
        $this->listener($url)->__invoke($event);

        self::assertNull($event->getResponse());
        self::assertSame(LeagueClientSynchronizer::hashClientId($url), $request->query->get('client_id'));
        self::assertSame($url, $request->attributes->get('mcp_oauth.original_client_id'));
        self::assertSame('Claude', $request->attributes->get('mcp_oauth.client_name'));
    }

    public function testIgnoresOpaqueClientId(): void
    {
        $request = Request::create('https://mcp.example.test/oauth2/authorize', 'GET', [
            'scope' => 'mcp',
            'client_id' => 'already-registered',
        ]);
        $this->listener('https://claude.ai/oauth/client-metadata.json')->__invoke($this->event($request));

        self::assertSame('already-registered', $request->query->get('client_id'));
    }

    private function listener(string $metadataUrl): CimdRequestListener
    {
        $settings = $this->settings();
        $canonical = new CanonicalResourceUri();
        $guard = new McpRequestGuard($settings, new IssuerResolver($settings, $canonical), $canonical);
        $http = new MockHttpClient([
            new MockResponse(json_encode([
                'client_id' => $metadataUrl,
                'client_name' => 'Claude',
                'redirect_uris' => ['https://claude.ai/callback'],
            ], \JSON_THROW_ON_ERROR)),
        ]);
        $resolver = new ClientIdMetadataResolver($http, new ArrayAdapter(), $settings);

        return new CimdRequestListener($settings, $resolver, $guard);
    }

    private function event(Request $request): RequestEvent
    {
        return new RequestEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
        );
    }

    private function settings(): McpOauthSettings
    {
        return new McpOauthSettings(
            resourcePaths: ['/_mcp'],
            authorizationPrefix: '/oauth2',
            scopes: ['mcp'],
            loginRoute: 'app_login',
            redirectQueryParam: '_target_path',
            consent: 'page',
            cimdEnabled: true,
            trustedDomains: ['claude.ai'],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: true,
            publicBaseUrl: 'https://mcp.example.test',
        );
    }
}
