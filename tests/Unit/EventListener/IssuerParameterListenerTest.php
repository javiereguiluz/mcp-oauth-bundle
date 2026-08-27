<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\EventListener;

use Omouren\McpOauthBundle\EventListener\IssuerParameterListener;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\AuthorizationResponseIssuer;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

final class IssuerParameterListenerTest extends TestCase
{
    public function testAddsIssToLeagueGenericRedirectResponse(): void
    {
        $response = new Response('', 302, [
            'Location' => 'http://127.0.0.1:6274/oauth/callback?code=abc&state=xyz',
        ]);

        $this->listener()->__invoke($this->event(
            Request::create('https://admin.dev.frenchfounders.com/oauth2/authorize?scope=mcp'),
            $response,
        ));

        $location = $response->headers->get('Location');
        self::assertNotNull($location);
        self::assertStringContainsString('code=abc', $location);
        self::assertStringContainsString('iss=https%3A%2F%2Fadmin.dev.frenchfounders.com', $location);
        self::assertNotInstanceOf(RedirectResponse::class, $response);
    }

    public function testAlsoUpdatesSymfonyRedirectResponseTarget(): void
    {
        $response = new RedirectResponse('http://127.0.0.1:6274/oauth/callback?code=abc');

        $this->listener()->__invoke($this->event(
            Request::create('https://mcp.example.test/oauth2/authorize?scope=mcp'),
            $response,
        ));

        self::assertStringContainsString('iss=', $response->getTargetUrl());
        self::assertSame($response->getTargetUrl(), $response->headers->get('Location'));
    }

    public function testDoesNotAddIssToLoginRedirect(): void
    {
        $response = new RedirectResponse('/login?_target_path=%2Foauth2%2Fauthorize');

        $this->listener()->__invoke($this->event(
            Request::create('https://mcp.example.test/oauth2/authorize?scope=mcp'),
            $response,
        ));

        self::assertSame('/login?_target_path=%2Foauth2%2Fauthorize', $response->headers->get('Location'));
    }

    public function testDoesNotAddIssWhenRequestIsNotMcp(): void
    {
        $response = new Response('', 302, [
            'Location' => 'http://127.0.0.1:6274/oauth/callback?code=abc',
        ]);

        $this->listener()->__invoke($this->event(
            Request::create('https://mcp.example.test/oauth2/authorize?scope=api'),
            $response,
        ));

        self::assertSame('http://127.0.0.1:6274/oauth/callback?code=abc', $response->headers->get('Location'));
    }

    public function testSkipsWhenIssuerIdentificationIsDisabled(): void
    {
        $response = new Response('', 302, [
            'Location' => 'http://127.0.0.1:6274/oauth/callback?code=abc',
        ]);

        $this->listener(issuerIdentification: false)->__invoke($this->event(
            Request::create('https://mcp.example.test/oauth2/authorize?scope=mcp'),
            $response,
        ));

        self::assertSame('http://127.0.0.1:6274/oauth/callback?code=abc', $response->headers->get('Location'));
    }

    private function listener(bool $issuerIdentification = true): IssuerParameterListener
    {
        $settings = new McpOauthSettings(
            resourcePath: '/_mcp',
            authorizationPrefix: '/oauth2',
            scopes: ['mcp'],
            loginRoute: 'app_login',
            consent: 'auto',
            cimdEnabled: true,
            trustedDomains: [],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: $issuerIdentification,
            publicBaseUrl: null,
        );
        $canonical = new CanonicalResourceUri();
        $issuerResolver = new IssuerResolver($settings, $canonical);

        return new IssuerParameterListener(
            $settings,
            $issuerResolver,
            new McpRequestGuard($settings, $issuerResolver, $canonical),
            new AuthorizationResponseIssuer(),
        );
    }

    private function event(Request $request, Response $response): ResponseEvent
    {
        return new ResponseEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
            $response,
        );
    }
}
