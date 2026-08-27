<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use Omouren\McpOauthBundle\OAuth\ResourceAudienceValidator;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use PHPUnit\Framework\TestCase;

final class ResourceAudienceValidatorTest extends TestCase
{
    public function testAcceptsResourceOrAudClaim(): void
    {
        $validator = new ResourceAudienceValidator(new CanonicalResourceUri());
        $resource = 'https://mcp.example.test/_mcp';

        self::assertTrue($validator->tokenTargetsResource(['resource' => $resource], $resource));
        self::assertTrue($validator->tokenTargetsResource(['aud' => $resource], $resource));
        self::assertTrue($validator->tokenTargetsResource(['aud' => ['other', $resource]], $resource));
        self::assertFalse($validator->tokenTargetsResource(['aud' => 'some-client'], $resource));
    }
}
