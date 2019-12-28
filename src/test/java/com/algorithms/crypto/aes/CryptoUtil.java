package com.algorithms.crypto.aes;

import java.security.SecureRandom;

public class CryptoUtil {
	public static byte[] generateInitializationVector(int length) {
		byte[] iv = new byte[length];
		new SecureRandom().nextBytes(iv);
		return iv;
	}
}
