<?php

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * This services provides the AppID for U2F extension, which is needed for backwards compatibility with old versions
 */
readonly class U2FAppIDProvider
{
    public function __construct(private RequestStack $requestStack, private ?string $appIDoverride = null)
    {
    }

    /**
     * @param  Request  $request
     * @return string
     */
    private function getAppIDFromRequest(Request $request): string
    {
        //Taken from r/u2ftwoFactorBundle for backwards compatibility

        $scheme = $request->getScheme();
        $host = $request->getHost();
        $port = $request->getPort();

        $port = ($port === 80 || $port === 443) ? '' : ':' . $port;

        return $scheme . '://' . $host . $port;
    }

    /**
     * Returns the AppID for the U2F extension, needed for backwards compatibility with U2F registrations
     * @return string
     */
    public function getAppID(): string
    {
        //If we have a custom appID, use that
        if ($this->appIDoverride) {
            return $this->appIDoverride;
        }

        //Otherwise, use the current request to generate the appID
        $request = $this->requestStack->getCurrentRequest();
        if ($request === null) {
            throw new \RuntimeException('Request cannot be null.');
        }

        return $this->getAppIDFromRequest($request);
    }
}