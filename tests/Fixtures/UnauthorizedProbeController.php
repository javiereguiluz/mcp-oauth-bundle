<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Fixtures;

use Symfony\Component\HttpFoundation\Response;

final class UnauthorizedProbeController
{
    public function __invoke(): Response
    {
        return new Response('', Response::HTTP_UNAUTHORIZED);
    }
}
