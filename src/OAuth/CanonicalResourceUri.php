<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

final class CanonicalResourceUri
{
    public function combine(string $baseUrl, string $path): string
    {
        $base = rtrim($baseUrl, '/');
        if ('' === $path || '/' === $path) {
            return $base;
        }

        return $base.'/'.ltrim($path, '/');
    }

    public function matches(string $expected, string $actual): bool
    {
        return 0 === strcasecmp($this->normalize($expected), $this->normalize($actual));
    }

    public function normalize(string $uri): string
    {
        $parts = parse_url($uri);
        if (false === $parts || !isset($parts['scheme'], $parts['host'])) {
            return rtrim($uri, '/');
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        $port = isset($parts['port']) ? ':'.$parts['port'] : '';
        $path = $parts['path'] ?? '';
        if ('/' === $path) {
            $path = '';
        }

        return $scheme.'://'.$host.$port.$path;
    }
}
