<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

#[AsEventListener(event: KernelEvents::REQUEST, priority: 7)]
final readonly class LoginRedirectListener
{
    use TargetPathTrait;

    public function __construct(
        private McpOauthSettings $settings,
        private Security $security,
        private UrlGeneratorInterface $urlGenerator,
        private McpRequestGuard $mcpRequestGuard,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        if (!$this->mcpRequestGuard->isMcpAuthorize($request)) {
            return;
        }

        $user = $this->security->getUser();
        if ($user instanceof UserInterface) {
            return;
        }

        $login = $this->urlGenerator->generate($this->settings->loginRoute);
        $target = $request->getUri();
        $firewallName = $this->security->getFirewallConfig($request)?->getName();
        if (null !== $firewallName && $request->hasSession()) {
            $this->saveTargetPath($request->getSession(), $firewallName, $target);
        }
        $separator = str_contains($login, '?') ? '&' : '?';

        $event->setResponse(new RedirectResponse($login.$separator.rawurlencode($this->settings->redirectQueryParam).'='.rawurlencode($target)));
    }
}
