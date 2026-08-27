<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\JwtClaimReader;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Omouren\McpOauthBundle\OAuth\ResourceAudienceValidator;
use Omouren\McpOauthBundle\OAuth\WwwAuthenticateHeader;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

#[AsEventListener(event: KernelEvents::REQUEST, priority: -8)]
final readonly class ResourceAudienceListener
{
    public function __construct(
        private McpOauthSettings $settings,
        private IssuerResolver $issuerResolver,
        private JwtClaimReader $jwtClaimReader,
        private ResourceAudienceValidator $audienceValidator,
        private WwwAuthenticateHeader $wwwAuthenticateHeader,
        private McpRequestGuard $mcpRequestGuard,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        if (!$event->isMainRequest() || !$this->settings->resourceIndicators) {
            return;
        }

        $request = $event->getRequest();
        if (!$this->mcpRequestGuard->isResourcePath($request)) {
            return;
        }

        $header = $request->headers->get('Authorization', '');
        if (!str_starts_with($header, 'Bearer ')) {
            return;
        }

        $jwt = substr($header, 7);
        $claims = $this->jwtClaimReader->payload($jwt);
        if (null === $claims) {
            return;
        }

        $expected = $this->issuerResolver->resource($request);
        if ($this->audienceValidator->tokenTargetsResource($claims, $expected)) {
            return;
        }

        $response = new Response('', Response::HTTP_UNAUTHORIZED);
        $response->headers->set('WWW-Authenticate', $this->wwwAuthenticateHeader->format(
            $this->issuerResolver->protectedResourceMetadataUrl($request),
            $this->settings->scopes,
        ));
        $event->setResponse($response);
    }
}
