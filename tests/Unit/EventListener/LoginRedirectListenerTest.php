<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\EventListener;

use Omouren\McpOauthBundle\EventListener\LoginRedirectListener;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use PHPUnit\Framework\TestCase;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\User\UserInterface;

final class LoginRedirectListenerTest extends TestCase
{
    public function testRedirectsAnonymousUserWithDefaultTargetPathParam(): void
    {
        $request = Request::create('https://mcp.example.test/oauth2/authorize?scope=mcp');
        $event = $this->event($request);

        $this->listener()->__invoke($event);

        $response = $event->getResponse();
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame(
            '/login?_target_path='.rawurlencode('https://mcp.example.test/oauth2/authorize?scope=mcp'),
            $response->headers->get('Location'),
        );
    }

    public function testUsesConfiguredRedirectQueryParam(): void
    {
        $request = Request::create('https://mcp.example.test/oauth2/authorize?scope=mcp');
        $event = $this->event($request);

        $this->listener(redirectQueryParam: 'redirect_to')->__invoke($event);

        $response = $event->getResponse();
        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame(
            '/login?redirect_to='.rawurlencode('https://mcp.example.test/oauth2/authorize?scope=mcp'),
            $response->headers->get('Location'),
        );
    }

    public function testDoesNotRedirectWhenUserIsAuthenticated(): void
    {
        $request = Request::create('https://mcp.example.test/oauth2/authorize?scope=mcp');
        $event = $this->event($request);

        $this->listener(authenticated: true)->__invoke($event);

        self::assertNull($event->getResponse());
    }

    private function listener(string $redirectQueryParam = '_target_path', bool $authenticated = false): LoginRedirectListener
    {
        $settings = new McpOauthSettings(
            resourcePaths: ['/_mcp'],
            authorizationPrefix: '/oauth2',
            scopes: ['mcp'],
            loginRoute: 'app_login',
            redirectQueryParam: $redirectQueryParam,
            consent: 'page',
            cimdEnabled: true,
            trustedDomains: [],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: true,
            publicBaseUrl: 'https://mcp.example.test',
        );
        $canonical = new CanonicalResourceUri();
        $guard = new McpRequestGuard($settings, new IssuerResolver($settings, $canonical), $canonical);

        $security = $this->createMock(Security::class);
        $security->method('getUser')->willReturn($authenticated ? $this->createMock(UserInterface::class) : null);
        $security->method('getFirewallConfig')->willReturn(null);

        $urls = $this->createMock(UrlGeneratorInterface::class);
        $urls->method('generate')->with('app_login')->willReturn('/login');

        return new LoginRedirectListener($settings, $security, $urls, $guard);
    }

    private function event(Request $request): RequestEvent
    {
        return new RequestEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
        );
    }
}
