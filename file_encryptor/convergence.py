from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

from .settings import CHUNK_SIZE
from . import key_generators
from .ex import AuthenticationError

def get_hmac(key):
    return HMAC.new(SHA256.new(key).digest(), None, SHA256)


def encrypt_file_inline(filename, passphrase, return_hmac=False):
    """Encrypt file inline, with an optional passphrase.

    Returns the key that will be required in order to
    decrypt the file.

    If you set the passphrase to None, a default is used.
    This will make you vulnerable to confirmation attacks
    and learn-partial-information attacks.

    """
    k = key_generators.key_from_file(filename, passphrase)

    with open(filename,"r+b") as f:
        h = inline_encrypt(f, k)
    
    if (return_hmac):
        return k, h
    else:
        return k
    # return k.encode("hex")


def decrypt_file_inline(filename, k, hmac = None):
    """Decrypt file inline with key k.

    The given key must be the same that was
    returned by encrypt_file_inline.

    """
    with open(filename,"r+b") as f:
        inline_decrypt(f, k, hmac)


def decrypt_generator(filename, k, hmac = None):
    """Stream decrypted file with key k.

    The given key must be the same that was
    returned by encrypt_file_inline.
    """
    h = get_hmac(k)
    
    with open(filename, "rb") as f:
        for chunk in aes_transform(f, k, lambda x: h.update(x)):
            yield chunk
    
    if (hmac is not None and hmac != h.digest()):
        raise AuthenticationError("Hash Message Authentication Code invalid.")
    
def inline_encrypt(f, key):
    """Encrypt file inline.

    Encrypts a given file with the given key,
    and replaces it directly without any extra
    space requirement.
    
    Generates a hash message authentication
    code in order to later authenticate the file
    """
    
    h = get_hmac(key)
    
    inline_transform(f, aes_transform, (f,key, lambda x: None, lambda x: h.update(x)))
     
    return h.digest()


def inline_decrypt(f, key, hmac = None):
    """Decrypts a file inline.
    
    Decrypts a given file with the given key,
    and replaces it directly without any
    extra space requirement.
    
    Optionally checks the provided HMAC code
    against the encrypted file in order to
    ensure the file's authenticity
    """
    
    h = get_hmac(key)
    
    inline_transform(f, aes_transform, (f, key, lambda x: h.update(x)))
    
    if (hmac is not None and hmac != h.digest()):
        raise AuthenticationError("Hash Message Authentication Code invalid.")


def inline_transform(f, gen, args):
    """Transforms a file in place
    """
    
    pos = f.tell()
    for chunk in gen(*args):
        f.seek(pos)
        f.write(chunk)
        f.flush()
        pos = f.tell()


def aes_transform(f, key, pre = lambda x: None, post = lambda x: None):
    """Generate encrypted file with given key.

    This generator function reads the file
    in chunks and encrypts them using AES-CTR,
    with the specified key.
    
    Also has optional pre and post processing functions for each chunk

    """
    # We are not specifying the IV here.
    aes = AES.new(key, AES.MODE_CTR, counter=Counter.new(128))
    
    for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
        pre(chunk)
        chunk = aes.encrypt(chunk)
        post(chunk)
        yield chunk
