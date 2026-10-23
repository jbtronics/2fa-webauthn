<?php

declare(strict_types=1);

namespace Jbtronics\TFAWebauthn\Tests\Fixtures;

use Jbtronics\TFAWebauthn\Model\LegacyU2FKeyInterface;
use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialUserEntity;

final class TestUser implements UserInterface, TwoFactorInterface
{
    /**
     * @param list<CredentialRecord>      $webauthnKeys
     * @param list<LegacyU2FKeyInterface> $legacyKeys
     */
    public function __construct(
        private readonly array $webauthnKeys = [],
        private readonly array $legacyKeys = [],
        private readonly bool $enabled = true,
    ) {
    }

    public function getRoles(): array
    {
        return ['ROLE_USER'];
    }

    public function eraseCredentials(): void
    {
    }

    public function getUserIdentifier(): string
    {
        return 'alice';
    }

    public function isWebAuthnAuthenticatorEnabled(): bool
    {
        return $this->enabled;
    }

    public function getLegacyU2FKeys(): iterable
    {
        return $this->legacyKeys;
    }

    public function getWebauthnKeys(): iterable
    {
        return $this->webauthnKeys;
    }

    public function getWebAuthnUser(): PublicKeyCredentialUserEntity
    {
        return PublicKeyCredentialUserEntity::create('alice', 'alice-id', 'Alice');
    }
}
