# node-pki-signer

Fast, in-process X.509 signing for [PKIaaS.io](https://pkiaas.io) and the [IoT HSM](https://github.com/lspiehler/iot-hsm) agent.

It signs certificates with software keys, PKCS#11 tokens (YubiKey, SoftHSM) and Google Cloud KMS, including post-quantum keys (ML-DSA, SLH-DSA). Anything it can't do natively falls back to OpenSSL, so new algorithms work as soon as OpenSSL supports them.

Status: early development, not yet published.
