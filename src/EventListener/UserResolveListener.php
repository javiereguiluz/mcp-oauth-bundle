<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use League\Bundle\OAuth2ServerBundle\Event\UserResolveEvent;
use League\Bundle\OAuth2ServerBundle\OAuth2Events;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[AsEventListener(event: OAuth2Events::USER_RESOLVE)]
final readonly class UserResolveListener
{
    public function __construct(
        private TokenStorageInterface $tokenStorage,
        private RequestStack $requestStack,
        private McpRequestGuard $mcpRequestGuard,
    ) {
    }

    public function __invoke(UserResolveEvent $event): void
    {
        $request = $this->requestStack->getCurrentRequest();
        if (null === $request || !$this->mcpRequestGuard->isMcpToken($request)) {
            return;
        }

        $user = $this->tokenStorage->getToken()?->getUser();
        if ($user instanceof UserInterface) {
            $event->setUser($user);
        }
    }
}
