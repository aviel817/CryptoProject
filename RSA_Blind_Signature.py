from random import randrange, random
from collections import namedtuple
from math import log, gcd
from binascii import hexlify, unhexlify


def is_prime(n, k=30):
    '''
    Description: checks if input is prime \n
    input:  prime number, number of rounds \n
    output: true for prime false for not prime
    '''
    if n <= 3:
        return n == 2 or n == 3
    neg_one = n - 1

    s, d = 0, neg_one
    while not d & 1:
        s, d = s + 1, d >> 1
    assert 2 ** s * d == neg_one and d & 1

    for i in range(k):
        a = randrange(2, neg_one)
        x = pow(a, d, n)
        if x in (1, neg_one):
            continue
        for r in range(1, s):
            x = x ** 2 % n
            if x == 1:
                return False
            if x == neg_one:
                break
        else:
            return False
    return True


def randprime(N=10 ** 8):
    '''
    Description: This function sets random prime number. \n
    input:  size of prime (should be big enough so it will be hard enough to decrypt it) \n
    output: random prime number at size of 10^8
    '''
    p = 1
    while not is_prime(p):
        p = randrange(N)
    return p


def multinv(modulus, value):
    '''
    Description: Calculate inverse of number modulus \n
    input:  modulus number, value \n
    output: inverse of value mod modulus
    '''
    x, lastx = 0, 1
    a, b = modulus, value
    while b:
        a, q, b = b, a // b, a % b
        x, lastx = lastx - q * x, x
    result = (1 - lastx * modulus) // value
    if result < 0:
        result += modulus
    assert 0 <= result < modulus and value * result % modulus == 1
    return result


KeyPair = namedtuple('KeyPair', 'public private')
Key = namedtuple('Key', 'exponent modulus')


def keygen(N, public=None):
    '''
    Description: compute pair of encrpyt key and decrypt key. \n
    input:  size of prime number \n
    output: key pair with encrypt(public) and decrypt key(private)
    '''
    prime1 = randprime(N)
    prime2 = randprime(N)
    composite = prime1 * prime2  # n=p*q
    totient = (prime1 - 1) * (prime2 - 1)  # euler(n)=(p-1)(q-1)

    if public is None:
        while True:
            private = randrange(totient)
            if gcd(private, totient) == 1:
                break
        public = multinv(totient, private)
    else:
        private = multinv(totient, public)
    assert public * private % totient == gcd(public, totient) == gcd(private, totient) == 1
    assert pow(pow(1234567, public, composite), private, composite) == 1234567
    return KeyPair(Key(public, composite), Key(private, composite))


def signature(msg, privkey):
    '''
    Description: raise msg by key provided \n
    input:  msg, pair -> key[0] = private/pubic key, key[1] = modulus of key \n
    output: msg^key mod n
    '''
    coded = pow(int(msg), *privkey) % privkey[1]
    return str(coded)


def blindingfactor(N):
    '''
    Description: Finds random prime netween 0 to N + checks its gcd(r,N)=1 as requers in formula\n
    input:  n - the modulus of key\n
    output: random prime number
    '''
    b = random() * (N - 1)
    r = int(b)
    while (gcd(r, N) != 1):
        r = r + 1
    return r


def blind(msg, pubkey):
    '''
    Description: Blind msg by multiply msg with randomNumber^publickKey as requerd in formula.
    input:  msg to blind, public key
    output: pair-> (random number calculated with blinding factor, the blinded msg)
    '''
    r = blindingfactor(pubkey[1])
    m = int(msg)
    blindmsg = (pow(r, *pubkey) * m) % pubkey[1]
    print
    "Blinded Message " + str(blindmsg)
    return (r, str(blindmsg))


def unblind(msg, r, pubkey):
    '''
    Description: Unblind given msg by multiply with inverse of random number given. \n
    input:  blindedMsg,random number,publick key \n
    output: unblinded msg
    '''
    bsm = int(msg)
    ubsm = (bsm * multinv(pubkey[1], r)) % pubkey[1]  # msg * r^-1 mod n

    return str(ubsm)


def verifySignature(msg1, msg2, senderPublicKey, receiverPrivateKey):
    '''
    Description: Verify sender identity\n
    input:  \n
    msg1 - senders secured it with his private key (only he can encrypt it)\n
    msg2 - sender secure it with publick key of receiver (only receiver can decrypt it)\n
    public key of sender to check with msg1\n
    private key of receiver to check with msg2\n
    output: return undersign msg
    '''
    if signature(msg1, senderPublicKey) == signature(msg2, receiverPrivateKey):
        print("Confirmed!")
    else:
        print("Failed")
    return signature(msg1, senderPublicKey)


def RSAsecureMsg(MsgToSecure, privateKey, publicKey):
    '''
    Description: secure msg with private key of sender and public key of receiver\n
    input:  msg to secure, private key of sender and public key of receiver\n
    output: return pair of secured msg
    '''
    signatureOfSender = signature(MsgToSecure, privateKey)
    signatureOfReceiver = signature(MsgToSecure, publicKey)
    return (signatureOfSender, signatureOfReceiver)
