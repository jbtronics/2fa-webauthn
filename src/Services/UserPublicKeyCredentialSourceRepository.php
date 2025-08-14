<?php

namespace Jbtronics\TFAWebauthn\Services;

use Jbtronics\TFAWebauthn\Helpers\WebsafeBase64;
use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * This class provides the public key credential sources, normalize legacy U2F keys and merges U2F and Webauthn keys.
 */
readonly class UserPublicKeyCredentialSourceRepository
{
    public function __construct(private Security $security)
    {
    }


    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $all_keys = $this->findAllForCurrentUser();

        foreach ($all_keys as $key) {
            if ($key->publicKeyCredentialId === $publicKeyCredentialId) {
                return $key;
            }
        }

        return null;
    }

    /**
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForCurrentUser(): array
    {
        $user = $this->security->getUser();
        if(!$user instanceof TwoFactorInterface) {
            return [];
        }

        $result = [];

        //Add the legacy credentials
        foreach ($user->getLegacyU2FKeys() as $legacyU2FKey)
        {
            $result[] = new PublicKeyCredentialSource(
                WebsafeBase64::decodeToBinary($legacyU2FKey->getKeyHandle()),
                'public-key',
                [],
                'none', //dummy
                new EmptyTrustPath(), //dummy
                Uuid::v4(), //dummy,
                base64_decode($legacyU2FKey->getPublicKey()),
                $user->getWebAuthnUser()->id,
                0 //must be 0 to disable counter checking
            );
        }

        //Add the new webauthn keys
        return array_merge($result, iterator_to_array($user->getWebAuthnKeys()));
    }

    /**
     * @param  PublicKeyCredentialUserEntity  $publicKeyCredentialUserEntity
     * @return PublicKeyCredentialSource[]
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        return $this->findAllForCurrentUser();
    }
}