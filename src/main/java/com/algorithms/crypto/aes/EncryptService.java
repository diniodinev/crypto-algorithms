package com.algorithms.crypto.aes;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public interface EncryptService {

    byte[] encryptMessage(byte[] message, byte[] keyBytes) throws InvalidKeyException, NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException;

    byte[] encryptMessage(byte[] message, Certificate publicKeyCertificate) throws InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException;

    byte[] decryptMessage(byte[] encryptedMessage, byte[] keyBytes) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException;

}