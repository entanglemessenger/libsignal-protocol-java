/**
 * Copyright (C) 2013-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.ecc;

import java.security.PublicKey;
import java.util.Arrays;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;
import org.whispersystems.curve25519.VrfSignatureVerificationFailedException;
import org.whispersystems.libsignal.InvalidKeyException;

import org.whispersystems.libsignal.ecc.sidh.NativeSidhPrivateKey;
import org.whispersystems.libsignal.ecc.sidh.NativeSidhPublicKey;

import static org.whispersystems.curve25519.Curve25519.BEST;
import org.pqcrypto.sidh.NativeSIDHProvider;

public class Curve {

  public static final int DJB_TYPE  = 0x05;
  public static final int NSIDH_TYPE = 0x08;
  public static final NativeSIDHProvider sidh = new NativeSIDHProvider();

  public static boolean isNative() {
    return Curve25519.getInstance(BEST).isNative();
  }

  public static ECKeyPair generateKeyPair(int type) {

    switch (type) {
      case Curve.DJB_TYPE:
        Curve25519KeyPair keyPair = Curve25519.getInstance(BEST).generateKeyPair();
        return new ECKeyPair(new DjbECPublicKey(keyPair.getPublicKey()),
                new DjbECPrivateKey(keyPair.getPrivateKey()));

      case Curve.NSIDH_TYPE:
        // generate kp for signatures (non-pq)
        Curve25519KeyPair ecKeyPair = Curve25519.getInstance(BEST).generateKeyPair();

        byte[] privKeyA = sidh.generatePrivateKeyA();
        byte[] privKeyB = sidh.generatePrivateKeyB();

        NativeSidhPrivateKey privKey = new NativeSidhPrivateKey(privKeyA, privKeyB,
                                                                ecKeyPair.getPrivateKey());
        NativeSidhPublicKey pubKey = new NativeSidhPublicKey(sidh.generatePublicKeyA(privKeyA),
                                                            sidh.generatePublicKeyB(privKeyB),
                                                            ecKeyPair.getPublicKey());
        return new ECKeyPair(pubKey, privKey);

      default:
        return null;
    }

  }

  // set default to the normal case for now
  public static ECKeyPair generateKeyPair() {
    return generateKeyPair(Curve.NSIDH_TYPE);
  }

  public static ECPublicKey decodePoint(byte[] bytes, int offset)
      throws InvalidKeyException
  {
    if (bytes.length - offset < 1) {
      throw new InvalidKeyException("No key type identifier");
    }

    int type = bytes[offset] & 0xFF;

    switch (type) {
      case Curve.DJB_TYPE:
        if (bytes.length - offset < ECPublicKey.KEY_SIZE) {
          throw new InvalidKeyException("Bad key length: " + bytes.length);
        }
        byte[] keyBytes = new byte[32];
        System.arraycopy(bytes, offset+1, keyBytes, 0, keyBytes.length);
        return new DjbECPublicKey(keyBytes);

      case Curve.NSIDH_TYPE:
        byte[] nskeyBytes = new byte[bytes.length-1 - offset];
        System.arraycopy(bytes, offset+1, nskeyBytes, 0, nskeyBytes.length);
        return new NativeSidhPublicKey(nskeyBytes);

      default:
        throw new InvalidKeyException("Bad key type: " + type);
    }
  }

  public static ECPrivateKey decodePrivatePoint(byte[] bytes) {
    int type = bytes[0] & 0xFF;
    final int eccPrivKeyLen = 32;

    /*// Backwards compatibility with test suite due to manually keyed in keys
    if(bytes.length == eccPrivKeyLen) {
      return new DjbECPrivateKey(bytes);
    }*/

    switch (type) {
      case Curve.DJB_TYPE:
        byte[] keyBytes = new byte[eccPrivKeyLen];
        System.arraycopy(bytes, 1, keyBytes, 0, keyBytes.length);
        return new DjbECPrivateKey(keyBytes);

      case Curve.NSIDH_TYPE:
        byte[] nskeyBytes = new byte[bytes.length-1];
        System.arraycopy(bytes, 1, nskeyBytes, 0, nskeyBytes.length);
        return new NativeSidhPrivateKey(nskeyBytes);

      default:
        return null;
    }
  }

  public static byte[] calculateAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)
      throws InvalidKeyException
  {
    if (publicKey.getType() != privateKey.getType()) {
      throw new InvalidKeyException("Public and private keys must be of the same type!");
    }

    if (publicKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
              .calculateAgreement(((DjbECPublicKey) publicKey).getPublicKey(),
                      ((DjbECPrivateKey) privateKey).getPrivateKey());
    } else if(publicKey.getType() == NSIDH_TYPE) {
        // perform double SIDH to create symmetry
        byte [] secretKey1 = sidh.calculateAgreementA(((NativeSidhPrivateKey)privateKey).getA(),
                                                          ((NativeSidhPublicKey)publicKey).getB());
        byte [] secretKey2 = sidh.calculateAgreementB(((NativeSidhPrivateKey)privateKey).getB(),
                                                          ((NativeSidhPublicKey)publicKey).getA());
        byte [] secretKey = new byte[secretKey1.length];
        for(int i=0; i<secretKey1.length; i++) {
          secretKey[i] = (byte) (secretKey1[i] ^ secretKey2[i]);
        }
        return secretKey;
    } else {
      throw new InvalidKeyException("Unknown type: " + publicKey.getType());
    }
  }

  public static boolean verifySignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException
  {
    if (signingKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
              .verifySignature(((DjbECPublicKey) signingKey).getPublicKey(), message, signature);
    } else if(signingKey.getType() == NSIDH_TYPE) {
      // use the non-pq ec key here until we have a pq replacement
      return Curve25519.getInstance(BEST)
              .verifySignature(((NativeSidhPublicKey) signingKey).getEcPubKey(), message, signature);
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }

  public static byte[] calculateSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    if (signingKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
                       .calculateSignature(((DjbECPrivateKey) signingKey).getPrivateKey(), message);
    } else if(signingKey.getType() == NSIDH_TYPE) {
      // use the non-pq ec key here until we have a pq replacement
      return Curve25519.getInstance(BEST)
              .calculateSignature(((NativeSidhPrivateKey) signingKey).getEcPrivKey(), message);
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }

  public static byte[] calculateVrfSignature(ECPrivateKey signingKey, byte[] message)
      throws InvalidKeyException
  {
    if (signingKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
                       .calculateVrfSignature(((DjbECPrivateKey)signingKey).getPrivateKey(), message);

    } else if(signingKey.getType() == NSIDH_TYPE) {
      // use the non-pq ec key here until we have a pq replacement
      return Curve25519.getInstance(BEST)
              .calculateVrfSignature(((NativeSidhPrivateKey)signingKey).getEcPrivKey(), message);
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }

  public static byte[] verifyVrfSignature(ECPublicKey signingKey, byte[] message, byte[] signature)
      throws InvalidKeyException, VrfSignatureVerificationFailedException
  {
    if (signingKey.getType() == DJB_TYPE) {
      return Curve25519.getInstance(BEST)
                       .verifyVrfSignature(((DjbECPublicKey) signingKey).getPublicKey(), message, signature);
    } else if(signingKey.getType() == NSIDH_TYPE) {
      // use the non-pq ec key here until we have a pq replacement
      return Curve25519.getInstance(BEST)
              .verifyVrfSignature(((NativeSidhPublicKey) signingKey).getEcPubKey(), message, signature);
    } else {
      throw new InvalidKeyException("Unknown type: " + signingKey.getType());
    }
  }

}
