## crypto

A simple library for converting a `[]byte` to a base64-encoded string and back.

The intended use is for web applications, so data can be stored in the user's HTML form instead of in the application itself. This is reduces exposure to resource-hogging DOS attacks, and reduces the need for cache expiration.

For example, the state of the user's session in any form, such as JSON, gob, or a `[]byte` from marshalling a struct, can be converted to a base64-encoded string and returned to the user as a `<input type="hidden">` field, to be returned with the subsequent `POST` request.

## Security

The obvious concern when accepting a value from the user is that it may have been tampered with. `crypto` uses [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code) to ensure that the message is returned exactly as it was provided. 

The [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption used ensures that the user can not access any of the data, so information such as session keys can be stored.

## Usage

    package main

    import (
        "fmt"
        "log"

        "github.com/shawnmilo/crypto"
    )

    func main() {
        password := "Nobody will guess this!"
        plainText := "The secret meeting is in the treehouse after school."

        fmt.Printf("original: %q\n", plainText)
        encrypted, err := crypto.Encrypt(password, []byte(plainText))
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("encrypted: %q\n", encrypted)
        decrypted, err := crypto.Decrypt(password, encrypted)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Printf("decrypted: %q\n", string(decrypted))
    }

Output:

    original: "The secret meeting is in the treehouse after school."
    encrypted: "sSvYMQQgLYsf2QmMxrN093YBZNiCU7rYNIQEWRAi+3i1Mmw7FDxc9+d6GNaNjEad4XIKwRtX+IpLE+ZrU1PLhPVMuA1upK4VxX0XxtIlqOBGzMrFYh3t2535fJxgav5j1lH/Cg=="
    decrypted: "The secret meeting is in the treehouse after school."

Note that the encrypted output will be different each time, even for the same input. This is due to AES's use of an [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector).

## License

BSD license.

## Credits

I was greatly helped by [this Stackoverflow response](http://stackoverflow.com/a/18819040), as well as the documentation from the Go standard library:

* [hmac](https://golang.org/pkg/crypto/hmac/)
* [base64](https://golang.org/pkg/encoding/base64/)

----

This technique is not original to me, and has probably been independently created my many others. I learned it from [Steve Gibson](https://twitter.com/sggrc), founder of [Gibson Research Corporation](https://www.grc.com/) and creator of [SpinRite](https://www.grc.com/sr/spinrite.htm).

Steve Gibson also explained the reasons using HMAC authentication is important, as well as why the authentication should be done _after_ encryption, not before, on the [Security Now](https://www.grc.com/securitynow.htm) podcast.

Specifically, this was explained while discussing InstantCryptor on episodes 497 and 499. See the Security Now link for access to audio and text from those episodes.
