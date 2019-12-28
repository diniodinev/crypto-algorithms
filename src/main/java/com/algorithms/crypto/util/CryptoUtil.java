package com.algorithms.crypto.util;

import java.security.SecureRandom;

public class CryptoUtil {
	public static byte[] generateInitializationVector(int length) {
		byte[] iv = new byte[length];
		new SecureRandom().nextBytes(iv);
		return iv;
	}
}
