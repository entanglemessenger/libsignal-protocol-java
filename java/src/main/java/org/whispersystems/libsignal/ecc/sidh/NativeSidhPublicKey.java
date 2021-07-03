package org.whispersystems.libsignal.ecc.sidh;

import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.util.ByteUtil;

import java.math.BigInteger;

import java.util.Arrays;

public class NativeSidhPublicKey implements ECPublicKey {
    public static final int KEY_SIZE = 378;
    public static final int EC_KEY_SIZE = 32;
    private byte [] pubKeyA;
    private byte [] pubKeyB;
    private byte [] ecPubKey;

    public NativeSidhPublicKey(byte[] bytesIn) {
        pubKeyA = new byte[KEY_SIZE];
        pubKeyB = new byte[KEY_SIZE];
        ecPubKey = new byte[EC_KEY_SIZE];

        System.arraycopy(bytesIn, 0, pubKeyA, 0, KEY_SIZE);
        System.arraycopy(bytesIn, KEY_SIZE, pubKeyB, 0, KEY_SIZE);
        System.arraycopy(bytesIn, KEY_SIZE*2, ecPubKey, 0, ecPubKey.length);
    }

    public NativeSidhPublicKey(byte[] _pubKeyA, byte[] _pubKeyB, byte[] _ecPubKey) {
        pubKeyA = _pubKeyA;
        pubKeyB = _pubKeyB;
        ecPubKey = _ecPubKey;
    }

    @Override
    public int getType() {
        return Curve.NSIDH_TYPE;
    }

    public byte [] getA() { return pubKeyA; }

    public byte [] getB() { return pubKeyB; }

    public byte [] getEcPubKey() { return ecPubKey; }

    @Override
    public boolean equals(Object other) {
        if (other == null) return false;
        if (!(other instanceof NativeSidhPublicKey)) return false;

        NativeSidhPublicKey o = (NativeSidhPublicKey) other;

        return Arrays.equals(pubKeyA, o.getA()) && Arrays.equals(pubKeyB, o.getB());
    }

    @Override
    public int compareTo(ECPublicKey another) {

        // TODO: This result may not be 'sensible' given the representation
        // TODO: Need to determine if/how this is actually used
        return new BigInteger(serialize()).compareTo(new BigInteger(((NativeSidhPublicKey) another).serialize()));
    }

    public byte[] serialize() {
        byte[] result;

        result = new byte[KEY_SIZE * 2 + ecPubKey.length];

        System.arraycopy(pubKeyA, 0, result, 0, KEY_SIZE);
        System.arraycopy(pubKeyB, 0, result, KEY_SIZE, KEY_SIZE);
        System.arraycopy(ecPubKey, 0, result, KEY_SIZE*2, ecPubKey.length);

        byte[] type = {Curve.NSIDH_TYPE};
        return ByteUtil.combine(type, result);
    }
}
