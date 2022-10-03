# Webauthn Two-Factor-Authentictication Plugin for scheb/2fa

This repository contains a plugin for [scheb/2fa](https://github.com/scheb/2fa) that adds support for Webauthn authenticators (like a Yubikey) as a second factor.

## Feautures
* Support of all webauthn authenticators as second factor
* Supports multiple authenticators per user
* Backward compatibility for existing registered U2F keys (from [r/u2f-two-factor-bundle](https://github.com/darookee/u2f-two-factor-bundle))

## Installation
1. Install the bundle `composer require jbtronics/2fa-webauthn`
2. Enable the bundle in your `config/bundles.php` (normally done by Symfony flex automatically)
3. If you want to use the easy doctrine integration, add the web-authn symfony bundle: `composer require web-auth/webauthn-symfony-bundle`. You do not need to run the community recipe, as we just use the doctrine type definitons from the bundle. Add `new Webauthn\Bundle\WebauthnBundle()` to your `config/bundles.php`.

## Setup and Usage
After following the Installation steps, do the follwing steps to setup the library:
1. Add `Jbtronics\TFAWebauthn\Model\TwoFactorInterface` interface to your user entity:
```php
use Jbtronics\TFAWebauthn\Model\TwoFactorInterface as WebauthnTwoFactorInterface;

class User implements WebauthnTwoFactorInterface
{
    /** 
     * @var Collection<int, PublicKeyCredentialSource>
     * @ORM\OneToMany(targetEntity="App\Entity\WebauthnKey", mappedBy="user", cascade={"REMOVE"}, orphanRemoval=true)
     */
    private $webauthnKeys;
    
    /**
     * Determines whether the user has 2FA using Webauthn enabled
     * @return bool True if the webauthn 2FA is enabled, false otherwise
     */
    public function isWebAuthnAuthenticatorEnabled(): bool
    {
        //Return true to enable webauthn 2FA
        return count($this->webauthnKeys) > 0;
    }
    
    /**
     * Returns a list of all legacy U2F keys, associated with this user
     * Return an empty array, if this user does not have any legacy U2F keys.
     * @return iterable<LegacyU2FKeyInterface>
     */
    public function getLegacyU2FKeys(): iterable
    {
        return []; //If you have no legacy U2F keys, return just an empty array
        //return $this->u2f_keys; //Otherwise return the legacy keys (see migration section below)
    }

    /**
     * Returns a list of all webauthn keys, associated with this user
     * @return iterable<PublicKeyCredentialSource>
     */
    public function getWebauthnKeys(): iterable
    {
        return $this->webauthnKeys;
    }

    /**
     * Returns the webauthn user entity that should be used for this user.
     * @return PublicKeyCredentialUserEntity
     */
    public function getWebAuthnUser(): PublicKeyCredentialUserEntity
    {
        //Return webauthn user definition for this user. As we just use it as an two-factor authentication, the values here are most likely not that important
        return new PublicKeyCredentialUserEntity(
            $this->getUsername(), // The Webauthn Name (like a username)
            $this->getID(), // A unique identifier for this user
            $this->getDisplayName() // The display name of this user (optional, otherwise null)
        );
    }
}
```

2. Create a new entity for the webauthn keys. For simplicity we use the templates from the web-auth/webauthn-symfony-bundle (see [here](https://webauthn-doc.spomky-labs.com/v/v3.3/the-webauthn-server/the-symfony-way/entities-with-doctrine) for more infos)
```php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Ramsey\Uuid\Uuid;
use Ramsey\Uuid\UuidInterface;
use Webauthn\PublicKeyCredentialSource as BasePublicKeyCredentialSource;
use Webauthn\TrustPath\TrustPath;

/**
 * @ORM\Table(name="webauthn_keys")
 * @ORM\Entity()
 */
class WebAuthnKey extends BasePublicKeyCredentialSource
{
    /**
     * @var string
     * @ORM\Id
     * @ORM\Column(type="string", length=100)
     * @ORM\GeneratedValue(strategy="NONE")
     */
    private $id;
    
    /**
     * @ORM\ManyToOne(targetEntity="App\Entity\User", inversedBy="webauthnKeys")
     **/
    protected ?User $user = null;
    
    //You can declare additional fields too, if you want to store additional information about the key (like a name)

    public function __construct(string $publicKeyCredentialId, string $type, array $transports, string $attestationType, TrustPath $trustPath, UuidInterface $aaguid, string $credentialPublicKey, string $userHandle, int $counter)
    {
        $this->id = Uuid::uuid4()->toString();
        parent::__construct($publicKeyCredentialId, $type, $transports, $attestationType, $trustPath, $aaguid, $credentialPublicKey, $userHandle, $counter);
    }

    public function getId(): string
    {
        return $this->id;
    }
}

```

3. Include javascript frontend code into your project: For webauthn we need some javascript code to interact with the authenticators.
Copy the file from `src/Resources/assets/tfa_webauthn.js` to your project and include it either by loading it via a `<script>` tag or by including it in your webpack using `.addEntry()`.

4. Add configuration file `config/packages/jbtronics_2fa_webauthn.yaml`:
```yaml
tfa_webauthn:
  enabled: true
  
  # Optional configuration options:

  # timeout: 60000 # The timeout in millisceconds to allow the user to interact with the authenticator. Default: 60000
  # template: '' # The template to use for the login form
  
  # rpID: null # The relying party ID of your application. If null, the current host will be used. Default: null
  # U2FAppID: null # The U2F AppID of your application. If null, the current host will be used. Default: null
  
  # These settings are most likely not important for two-factor authentication:
  # rpName: 'My Application' # The relying party name of your application, Default: 'My Application'
  # rpIcon: null # The relying party icon of your application. Default: null
```

5. Customize the login template: Similar to the base login template of the `scheb/2fa` bundle you will most likely need to override the login template of this bundle to integrate it into your design.
Copy the template from `Resources/views/Authentication/form.html.twig` to your project and customize it to your needs. Configure the `template` setting in the bundle config to your new path. 

## Registration of new keys
In principle the login with exsting keys should work now, but you will most likely need some possibility to register new keys. To make this easy there is the `Jbtronics\TFAWebauthn\Services\TFAWebauthnRegistrationHelper` service to help you with this:

1. Create a new controller, which will handle the registration, which should looks like this:
```php
    use Jbtronics\TFAWebauthn\Services\TFAWebauthnRegistrationHelper;Ä
    
    class WebauthnKeyRegistrationController extends AbstractController
{
    /**
     * @Route("/webauthn/register", name="webauthn_register")
     */
    public function register(Request $request, TFAWebauthnRegistrationHelper $registrationHelper)
    {

        //If form was submitted, check the auth response
        if ($request->getMethod() === 'POST') {
            $webauthnResponse = $request->request->get('_auth_code');

            //Retrieve other data from the form, that you want to store with the key
            $keyName = $request->request->get('keyName');


            try {
                //Check the response
                $new_key = $registrationHelper->checkRegistrationResponse($webauthnResponse);
            } catch (Exception $exception) {
                // Handle errors...
            }
            
            //If we got here, the registration was successful. Now we can store the new key in the database
            
            //TODO: Convert our returned key into an database entity and save it...
            
            
            $this->addFlash('success', 'Key registered successfully');
            //We are finished here so return to another page
            return $this->redirectToRoute('homepage');
        }


        return $this->render(
            'webauthn_register.html.twig',
            [
                //Generate the registration request
                'registrationRequest' => $registrationHelper->generateRegistrationRequestAsJSON(),
            ]
        );
    }
}
```

2. Create a template with a form, which will be used to register the new key. The form should look like this:
```html
<form method="post" class="form" action="{{ path('webauthn_register') }}" data-webauthn-tfa-action="register" data-webauthn-tfa-data='{{ registrationRequest|raw }}'>
    <input type="text" name="keyName" id="keyName" placeholder="Shown key name"/>
                
    <button type="submit" class="btn btn-success">Add new Key</button>
        
    <input type="hidden" name="_auth_code" id="_auth_code" />
        
</form>
```

The `data-webauthn-tfa-action` attribute marks the form as webauthn registration form and is handled by the frontend code included above.
If the form is submitted, the frontend code will catch that and start a registration process. The response is put it into the hidden input field with the id `_auth_code` and sent to our controller for parsing.

## Migrate from r/u2f-two-factor-bundle

1. Replace the `R\U2FTwoFactorBundle\Model\U2F\TwoFactorKeyInterface` interface of your U2FKey entity with `Jbtronics\TFAWebauthn\Model\LegacyU2FKeyInterface` and remove the constructor (as we do not need it anymore).
2. Replace the `R\U2FTwoFactorBundle\Model\U2F\TwoFactorInterface` interface of your user with `Jbtronics\TFAWebauthn\Model\TwoFactorInterface`, configure it (see above) and replace/rename your `getU2FKeys()` function to `getLegacyU2FKeys()`.
3. (Optional:) If your appID is not the same as your domain, configure it with the `U2FAppID` option. But this should normally not be needed
4. Remove the old routes, templates and settings of the `r/u2f-two-factor-bundle` and remove it from your application
5. Follow the setup steps above


## License
This bundle is licensed under the MIT license. See [LICENSE](LICENSE) for details.

## Credits
* Webauthn support is provided by [spomky-labs webauthn-framework](https://github.com/web-auth/webauthn-framework)
* This library is inspired by the [r/u2f-two-factor-bundle](r/u2f-two-factor-bundle) bundle
