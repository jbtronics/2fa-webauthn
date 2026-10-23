<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\RequestStack;

final readonly class PSRRequestHelper
{
    public function __construct(private RequestStack $requestStack)
    {
    }

    /**
     * Returns the current server request as PSR-7 request, or null if there is no current request.
     */
    public function getCurrentRequestAsPSR7(): ?ServerRequestInterface
    {
        $symfonyRequest = $this->requestStack->getCurrentRequest();
        if (null === $symfonyRequest) {
            return null;
        }

        $psr17Factory = new Psr17Factory();
        $psrHttpFactory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);

        return $psrHttpFactory->createRequest($symfonyRequest);
    }
}
