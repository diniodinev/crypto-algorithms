package com.algorithms.crypto.aes;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Base64.Decoder;

import org.apache.commons.codec.binary.Hex;
import org.junit.Before;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.springframework.util.ResourceUtils;

@RunWith(JUnit4.class)
public class EncryptServiceImplTest {

	AesEncryptServiceImpl encryptServiceImpl;
	private File file;

	//salt=C29CA36EDE523E87
	//		key=E8E2F6828F870C130D06A644C65728F1
	//		iv =848C35D3149B7CDC5CE20F7C8E8105A6

	@Before
	public void setUp() {
		encryptServiceImpl = new AesEncryptServiceImpl();
	}

	@Test
	public void encryptAndDecryptFileSuccessfullyWithAes() throws Exception {
		String originalContent = "foobar";
		file = ResourceUtils.getFile("classpath:certs/aes/aes.key");
		//Open SSl generate
		byte[] keyBytes = Hex.decodeHex(new String(Files.readAllBytes(file.toPath())));
		encryptServiceImpl = new AesEncryptServiceImpl();

		byte[] encryptedMessage = encryptServiceImpl.encryptMessage(originalContent.getBytes(), keyBytes);

		byte[] decryptedMessage = encryptServiceImpl.decryptMessage(encryptedMessage, keyBytes);
		assertThat(new String(decryptedMessage), is(originalContent));
	}
}
