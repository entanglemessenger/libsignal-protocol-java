package org.whispersystems.libsignal.ecc.sidh;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.util.ByteUtil;
import java.util.Arrays;

public class NativeSidhPrivateKey implements ECPrivateKey {
    public static final int KEY_SIZE = 32;
    public static final int EC_KEY_SIZE = 32;
    private byte [] privKeyA;
    private byte [] privKeyB;
    private byte [] ecPrivKey;

    public NativeSidhPrivateKey(byte[] bytesIn) {
        privKeyA = new byte[KEY_SIZE];
        privKeyB = new byte[KEY_SIZE];
        ecPrivKey = new byte[EC_KEY_SIZE];

        System.arraycopy(bytesIn, 0, privKeyA, 0, KEY_SIZE);
        System.arraycopy(bytesIn, KEY_SIZE, privKeyB, 0, KEY_SIZE);
        System.arraycopy(bytesIn, KEY_SIZE*2, ecPrivKey, 0, ecPrivKey.length);
    }

    public NativeSidhPrivateKey(byte[] _privKeyA, byte[] _privKeyB, byte[] _ecPrivKey) {
        privKeyA = _privKeyA;
        privKeyB = _privKeyB;
        ecPrivKey = _ecPrivKey;
    }

    @Override
    public int getType() {
        return Curve.NSIDH_TYPE;
    }

    public byte [] getA() { return privKeyA; }

    public byte [] getB() { return privKeyB; }

    public byte [] getEcPrivKey() { return ecPrivKey; }

    public boolean privateKeyEquals(NativeSidhPrivateKey k2) {
        return Arrays.equals(privKeyA, k2.getA()) && Arrays.equals(privKeyB, k2.getB());
    }

    public byte[] serialize() {
        byte[] result;

        result = new byte[KEY_SIZE * 2 + ecPrivKey.length];

        System.arraycopy(privKeyA, 0, result, 0, KEY_SIZE);
        System.arraycopy(privKeyB, 0, result, KEY_SIZE, KEY_SIZE);
        System.arraycopy(ecPrivKey, 0, result, KEY_SIZE*2, ecPrivKey.length);

        byte[] type = {Curve.NSIDH_TYPE};
        return ByteUtil.combine(type, result);
    }
}


