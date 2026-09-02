<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\Cimd;

use Omouren\McpOauthBundle\Cimd\CimdException;
use Omouren\McpOauthBundle\Cimd\ClientIdMetadataResolver;
use Omouren\McpOauthBundle\McpOauthSettings;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;

final class ClientIdMetadataResolverTest extends TestCase
{
    public function testFetchesAndParsesDocument(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $resolver = $this->resolver(new MockHttpClient([$this->documentResponse($url, 'Claude')]));

        $document = $resolver->resolve($url);

        self::assertSame($url, $document->clientId);
        self::assertSame('Claude', $document->clientName);
        self::assertSame(['https://claude.ai/api/mcp/auth_callback'], $document->redirectUris);
    }

    public function testCachesDocument(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $http = new MockHttpClient([
            $this->documentResponse($url, 'Claude'),
        ]);
        $resolver = $this->resolver($http);

        $resolver->resolve($url);
        $again = $resolver->resolve($url);

        self::assertSame('Claude', $again->clientName);
        self::assertSame(1, $http->getRequestsCount());
    }

    public function testAllowsSubdomainOfTrustedHost(): void
    {
        $url = 'https://www.claude.ai/oauth/client-metadata.json';
        $document = $this->resolver(new MockHttpClient([$this->documentResponse($url, 'Claude')]))->resolve($url);

        self::assertSame('Claude', $document->clientName);
    }

    public function testRejectsMismatchedClientId(): void
    {
        $url = 'https://claude.ai/oauth/client-metadata.json';
        $http = new MockHttpClient([
            $this->documentResponse('https://evil.example/client.json', 'Evil'),
        ]);

        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('does not match');
        $this->resolver($http)->resolve($url);
    }

    public function testRejectsUnknownHost(): void
    {
        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('allowlist');
        $this->resolver(new MockHttpClient())->resolve('https://evil.example/client.json');
    }

    public function testRejectsHttp(): void
    {
        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('https');
        $this->resolver(new MockHttpClient())->resolve('http://claude.ai/client.json');
    }

    public function testRejectsPrivateIp(): void
    {
        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('not allowed');
        $this->resolver(new MockHttpClient())->resolve('https://127.0.0.1/client.json');
    }

    public function testRejectsUrlWithoutPath(): void
    {
        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('path');
        $this->resolver(new MockHttpClient())->resolve('https://claude.ai');
    }

    public function testRejectsRedirectToPrivateIp(): void
    {
        $response = $this->createMock(ResponseInterface::class);
        $response->method('getInfo')->willReturn(['url' => 'https://127.0.0.1/stolen.json']);

        $http = $this->createMock(HttpClientInterface::class);
        $http->method('request')->willReturn($response);

        $this->expectException(CimdException::class);
        $this->expectExceptionMessage('not allowed');
        $this->resolver($http)->resolve('https://claude.ai/oauth/client-metadata.json');
    }

    private function resolver(HttpClientInterface $http): ClientIdMetadataResolver
    {
        return new ClientIdMetadataResolver($http, new ArrayAdapter(), $this->settings());
    }

    private function documentResponse(string $clientId, string $name): MockResponse
    {
        return new MockResponse(json_encode([
            'client_id' => $clientId,
            'client_name' => $name,
            'redirect_uris' => ['https://claude.ai/api/mcp/auth_callback'],
        ], \JSON_THROW_ON_ERROR), [
            'http_code' => 200,
            'response_headers' => ['content-type' => 'application/json'],
        ]);
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
            publicBaseUrl: null,
        );
    }
}
