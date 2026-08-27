<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

use League\Bundle\OAuth2ServerBundle\Manager\ClientManagerInterface;
use League\Bundle\OAuth2ServerBundle\Model\Client;
use League\Bundle\OAuth2ServerBundle\OAuth2Grants;
use League\Bundle\OAuth2ServerBundle\ValueObject\Grant;
use League\Bundle\OAuth2ServerBundle\ValueObject\RedirectUri;
use League\Bundle\OAuth2ServerBundle\ValueObject\Scope;
use Omouren\McpOauthBundle\Cimd\ClientIdMetadataDocument;
use Omouren\McpOauthBundle\McpOauthSettings;
use Symfony\Component\PasswordHasher\PasswordHasherInterface;

final readonly class LeagueClientSynchronizer
{
    public function __construct(
        private McpOauthSettings $settings,
        private ?ClientManagerInterface $clientManager = null,
        private ?PasswordHasherInterface $passwordHasher = null,
    ) {
    }

    /**
     * Doctrine `oauth2_client.identifier` is VARCHAR(32). A CIMD URL is not.
     *
     * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00
     *
     * @return non-empty-string
     */
    public static function hashClientId(string $clientIdUrl): string
    {
        return substr(hash('sha256', $clientIdUrl), 0, 32);
    }

    public function persistFromCimd(string $clientIdUrl, ClientIdMetadataDocument $document): string
    {
        $identifier = self::hashClientId($clientIdUrl);
        if (null === $this->clientManager) {
            return $identifier;
        }

        if (null !== $this->clientManager->find($identifier)) {
            return $identifier;
        }

        $client = new Client($document->clientName, $identifier, null);
        $this->configurePublicClient($client, $document->redirectUris);
        $this->clientManager->save($client);

        return $identifier;
    }

    /**
     * @param list<string> $redirectUris
     * @param list<string> $grantTypes
     * @param list<string> $scopes
     *
     * @return array{client_id: non-empty-string, client_secret: non-empty-string|null}
     */
    public function persistFromDcr(
        string $name,
        array $redirectUris,
        string $tokenEndpointAuthMethod,
        array $grantTypes,
        array $scopes,
    ): array {
        if (null === $this->clientManager) {
            throw new \LogicException('Dynamic client registration requires league/oauth2-server-bundle client persistence.');
        }

        $identifier = bin2hex(random_bytes(16));
        $plainSecret = 'none' === $tokenEndpointAuthMethod ? null : bin2hex(random_bytes(32));
        $storedSecret = null === $plainSecret || null === $this->passwordHasher
            ? $plainSecret
            : $this->passwordHasher->hash($plainSecret);

        $client = new Client($name, $identifier, $storedSecret);
        $this->configureClient($client, $redirectUris, $grantTypes, $scopes);
        $this->clientManager->save($client);

        return [
            'client_id' => $identifier,
            'client_secret' => $plainSecret,
        ];
    }

    /**
     * @param list<string> $redirectUris
     */
    private function configurePublicClient(Client $client, array $redirectUris): void
    {
        $this->configureClient(
            $client,
            $redirectUris,
            [OAuth2Grants::AUTHORIZATION_CODE, OAuth2Grants::REFRESH_TOKEN],
            $this->settings->scopes,
        );
    }

    /**
     * @param list<string> $redirectUris
     * @param list<string> $grantTypes
     * @param list<string> $scopes
     */
    private function configureClient(Client $client, array $redirectUris, array $grantTypes, array $scopes): void
    {
        $client->setActive(true);
        $client->setAllowPlainTextPkce(false);
        if ([] !== $redirectUris) {
            $client->setRedirectUris(...array_map(
                static fn (string $uri): RedirectUri => new RedirectUri($uri),
                $redirectUris,
            ));
        }
        $client->setGrants(...array_map(
            static fn (string $grantType): Grant => new Grant($grantType),
            $grantTypes,
        ));
        $client->setScopes(...array_map(
            static fn (string $scope): Scope => new Scope($scope),
            $scopes,
        ));
    }
}
