<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Services;

use Jbtronics\TFAWebauthn\Services\WebauthnProvider;
use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialRequestOptions;

final class WebauthnProviderTest extends TestCase
{
    public function testRpEntityUsesConfiguration(): void
    {
        $rp = (new WebauthnProvider('example.com', 'My App', null))->getPublicKeyCredentialRpEntity();

        self::assertSame('example.com', $rp->id);
        self::assertSame('My App', $rp->name);
    }

    public function testRpIdMayBeNull(): void
    {
        self::assertNull((new WebauthnProvider(null, 'My App', null))->getPublicKeyCredentialRpEntity()->id);
    }

    public function testServicesAreSharedInstances(): void
    {
        $provider = new WebauthnProvider('example.com', 'My App', null);

        self::assertSame($provider->getWebauthnSerializer(), $provider->getWebauthnSerializer());
        self::assertSame($provider->getAuthenticatorAssertionResponseValidator(), $provider->getAuthenticatorAssertionResponseValidator());
        self::assertSame($provider->getAuthenticatorAttestationResponseValidator(), $provider->getAuthenticatorAttestationResponseValidator());
    }

    public function testSerializerHandlesWebauthnObjects(): void
    {
        $serializer = (new WebauthnProvider('example.com', 'My App', null))->getWebauthnSerializer();
        $options = PublicKeyCredentialRequestOptions::create(challenge: 'challenge', rpId: 'example.com');

        $json = $serializer->serialize($options, 'json', ['skip_null_values' => true]);
        $decoded = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);
        self::assertSame('example.com', $decoded['rpId']);
        self::assertSame('Y2hhbGxlbmdl', $decoded['challenge'], 'binary fields are base64url encoded');
    }
}
