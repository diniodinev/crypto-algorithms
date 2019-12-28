package com.algorithms.crypto.aes;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import com.algorithms.crypto.util.CryptoUtil;

@Service
public class AesEncryptServiceImpl implements EncryptService {
	public static final int IV_LENGTH = 16;
	public static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

	@Override
	public byte[] encryptMessage(byte[] message, byte[] keyBytes) throws InvalidKeyException, NoSuchPaddingException,
			NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encryptedMessage = cipher.doFinal(message);
		return encryptedMessage;
	}

	public byte[] encryptMessage(byte[] message) throws InvalidKeyException, NoSuchPaddingException,
			NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = getCipher(generateSecretKey("AES"));
		return cipher.doFinal(message);
	}

	@Override
	public byte[] encryptMessage(byte[] message, Certificate publicKeyCertificate) throws InvalidKeyException,
			NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKeyCertificate);
		byte[] encryptedMessage = cipher.doFinal(message);
		return encryptedMessage;
	}

	@Override
	public byte[] decryptMessage(byte[] encryptedMessage, byte[] keyBytes) throws NoSuchPaddingException,
			NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] clearMessage = cipher.doFinal(encryptedMessage);
		return clearMessage;
	}

	public SecretKey generateSecretKey(String algorithType) {
		KeyGenerator kgen = null;
		try {
			kgen = KeyGenerator.getInstance(algorithType);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		return kgen.generateKey();
	}

	public Cipher getCipher(SecretKey skey) {
		Cipher ci = null;
		try {
			ci = Cipher.getInstance(TRANSFORMATION);

			SecureRandom srandom = new SecureRandom();
			byte[] iv = CryptoUtil.generateInitializationVector(IV_LENGTH);
			srandom.nextBytes(iv);
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			ci.init(Cipher.ENCRYPT_MODE, skey, ivspec);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return ci;
	}

}
