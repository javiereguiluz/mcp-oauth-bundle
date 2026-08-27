<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

final readonly class ConsentController
{
    public function __construct(
        private Environment $twig,
        private CsrfTokenManagerInterface $csrfTokenManager,
        private UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            $token = (string) $request->request->get('_csrf_token', '');
            if (!$this->csrfTokenManager->isTokenValid(new CsrfToken('mcp_oauth_consent', $token))) {
                return new Response('Invalid CSRF token.', Response::HTTP_FORBIDDEN);
            }

            $request->getSession()->set('mcp_oauth.consent_approved', true);
            $target = $this->urlGenerator->generate('oauth2_authorize', $request->query->all());

            return new Response('', Response::HTTP_FOUND, ['Location' => $target]);
        }

        $html = $this->twig->render('@McpOauth/consent.html.twig', [
            'client_name' => $request->query->get('client_name', 'MCP client'),
            'redirect_host' => $request->query->get('redirect_host', ''),
            'csrf_token' => $this->csrfTokenManager->getToken('mcp_oauth_consent')->getValue(),
        ]);

        return new Response($html);
    }
}
