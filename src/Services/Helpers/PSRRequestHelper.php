<?php

declare(strict_types=1);

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
     * Returns the current server request as PSR-7 request, or null if there is no current request.
     */
    public function getCurrentRequestAsPSR7(): ?ServerRequest
    {
        $symfonyRequest = $this->requestStack->getCurrentRequest();
        if (null === $symfonyRequest) {
            return null;
        }

        $psr17Factory = new Psr17Factory();
        $psrHttpFactory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);

        $request = $psrHttpFactory->createRequest($symfonyRequest);
        if (!$request instanceof ServerRequest) {
            throw new \LogicException(\sprintf('Expected a "%s", got a "%s".', ServerRequest::class, $request::class));
        }

        return $request;
    }
}
