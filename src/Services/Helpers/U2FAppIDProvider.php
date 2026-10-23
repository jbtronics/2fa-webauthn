<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * This services provides the AppID for U2F extension, which is needed for backwards compatibility with old versions.
 */
final readonly class U2FAppIDProvider
{
    public function __construct(private RequestStack $requestStack, private ?string $appIDoverride = null)
    {
    }

    /**
     * Returns the AppID for the U2F extension, needed for backwards compatibility with U2F registrations.
     */
    public function getAppID(): string
    {
        // If we have a custom appID, use that
        if (null !== $this->appIDoverride && '' !== $this->appIDoverride) {
            return $this->appIDoverride;
        }

        // Otherwise, use the current request to generate the appID
        $request = $this->requestStack->getCurrentRequest();
        if (null === $request) {
            throw new \RuntimeException('Request cannot be null.');
        }

        return $this->getAppIDFromRequest($request);
    }

    private function getAppIDFromRequest(Request $request): string
    {
        // Taken from r/u2ftwoFactorBundle for backwards compatibility
        $port = $request->getPort();
        $port = (80 === $port || 443 === $port) ? '' : ':'.$port;

        return $request->getScheme().'://'.$request->getHost().$port;
    }
}
