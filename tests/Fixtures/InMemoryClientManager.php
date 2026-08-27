<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Fixtures;

use League\Bundle\OAuth2ServerBundle\Manager\ClientFilter;
use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\ClientInterface;

final class InMemoryClientManager implements ClientManagerInterface
{
    /** @var array<string, ClientInterface> */
    private array $clients = [];

    public function save(ClientInterface $client): void
    {
        $this->clients[$client->getIdentifier()] = $client;
    }

    public function remove(ClientInterface $client): void
    {
        unset($this->clients[$client->getIdentifier()]);
    }

    public function find(string $identifier): ?ClientInterface
    {
        return $this->clients[$identifier] ?? null;
    }

    /**
     * @return list<ClientInterface>
     */
    public function list(?ClientFilter $clientFilter): array
    {
        return array_values($this->clients);
    }
}
