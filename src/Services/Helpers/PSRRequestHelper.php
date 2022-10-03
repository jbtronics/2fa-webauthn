<?php

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\RequestStack;

class PSRRequestHelper
{
    private RequestStack $requestStack;

    public function __construct(RequestStack $requestStack)
    {
        $this->requestStack = $requestStack;
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