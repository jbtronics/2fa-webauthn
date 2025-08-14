<?php

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\RequestStack;

readonly class PSRRequestHelper
{

    public function __construct(private RequestStack $requestStack)
    {
    }

    /**
     * Returns the current server request as PSR7 conform request
     * @return ServerRequest|null
     */
    public function getCurrentRequestAsPSR7(): ?ServerRequest
    {

        $symfonyRequest = $this->requestStack->getCurrentRequest();

        if ($symfonyRequest === null) {
            return null;
        }

        $psr17Factory = new Psr17Factory();
        $psrHttpFactory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);
        return $psrHttpFactory->createRequest($symfonyRequest);
    }
}