<?php

namespace Jbtronics\TFAWebauthn\Services\Helpers;

use Jbtronics\TFAWebauthn\Helpers\WebsafeBase64;
use Jbtronics\TFAWebauthn\Model\TwoFactorInterface;

class KeyCollector
{
    /**
     * This service collects all keys of a user and normalizes them into a form that we can use it with webauthn
     * @param  TwoFactorInterface  $user
     * @return array
     */
    public function collectKeyIDs(TwoFactorInterface $user): array
    {
        $keyIDs = [];

        //Collect legacy U2F keys first (we need to decode base64 to binary for the correct format, as r/u2f-bundle uses websafe base64 to store keyhandles)
        foreach ($user->getLegacyU2FKeys() as $key) {
            $keyIDs[] = WebsafeBase64::decodeToBinary($key->getKeyHandle());
        }

        return $keyIDs;
    }

    /**
     * This function search for a public key for a given key ID
     * @param  TwoFactorInterface  $user
     * @param  string  $keyID
     * @return string|null
     */
    public function findPublicKeyForID(TwoFactorInterface $user, string $keyID): ?string
    {
        //Collect legacy U2F keys first (we need to decode base64 to binary for the correct format, as r/u2f-bundle uses websafe base64 to store keyhandles)
        foreach ($user->getLegacyU2FKeys() as $key) {
            if (WebsafeBase64::decodeToBinary($key->getKeyHandle()) === $keyID) {
                return $key->getPublicKey();
            }
        }

        return null;
    }
}