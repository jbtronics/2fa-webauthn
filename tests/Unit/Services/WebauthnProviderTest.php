<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Unit\Services;

use Jbtronics\TFAWebauthn\Services\WebauthnProvider;
use PHPUnit\Framework\Attributes\IgnoreDeprecations;
use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialRequestOptions;

final class WebauthnProviderTest extends TestCase
{
    public function testRpNameIsNotSetWhenRpIdIsConfigured(): void
    {
        $provider = new WebauthnProvider('example.com', 'My App');
        $rp = $provider->getPublicKeyCredentialRpEntity();

        self::assertSame('example.com', $rp->id);
        self::assertSame('', $rp->name, 'the RP name is deprecated by web-auth/webauthn-lib');

        $json = json_decode($provider->getWebauthnSerializer()->serialize($rp, 'json'), true, flags: \JSON_THROW_ON_ERROR);
        self::assertIsArray($json);
        self::assertSame('example.com', $json['name'], 'browsers get the RP ID as name');
    }

    /**
     * Without an RP ID the name is still needed, which triggers the web-auth/webauthn-lib deprecation.
     */
    #[IgnoreDeprecations]
    public function testRpNameIsKeptWithoutRpId(): void
    {
        $rp = (new WebauthnProvider(null, 'My App'))->getPublicKeyCredentialRpEntity();

        self::assertNull($rp->id);
        self::assertSame('My App', $rp->name);
    }

    public function testServicesAreSharedInstances(): void
    {
        $provider = new WebauthnProvider('example.com', 'My App');

        self::assertSame($provider->getWebauthnSerializer(), $provider->getWebauthnSerializer());
        self::assertSame($provider->getAuthenticatorAssertionResponseValidator(), $provider->getAuthenticatorAssertionResponseValidator());
        self::assertSame($provider->getAuthenticatorAttestationResponseValidator(), $provider->getAuthenticatorAttestationResponseValidator());
    }

    public function testSerializerHandlesWebauthnObjects(): void
    {
        $serializer = (new WebauthnProvider('example.com', 'My App'))->getWebauthnSerializer();
        $options = PublicKeyCredentialRequestOptions::create(challenge: 'challenge', rpId: 'example.com');

        $json = $serializer->serialize($options, 'json', ['skip_null_values' => true]);
        $decoded = json_decode($json, true, flags: \JSON_THROW_ON_ERROR);

        self::assertIsArray($decoded);
        self::assertSame('example.com', $decoded['rpId']);
        self::assertSame('Y2hhbGxlbmdl', $decoded['challenge'], 'binary fields are base64url encoded');
    }
}
