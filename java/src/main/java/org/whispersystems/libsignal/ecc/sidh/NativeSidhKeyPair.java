package org.whispersystems.libsignal.ecc.sidh;

public class NativeSidhKeyPair {
    private final NativeSidhPublicKey pubKey;
    private final NativeSidhPrivateKey privKey;

    public NativeSidhKeyPair (NativeSidhPublicKey publicK, NativeSidhPrivateKey privateK) {
        pubKey = publicK;
        privKey = privateK;
    }

    public NativeSidhPublicKey getPublicKey() {
        return pubKey;
    }

    public NativeSidhPrivateKey getPrivateKey() {
        return privKey;
    }
}
