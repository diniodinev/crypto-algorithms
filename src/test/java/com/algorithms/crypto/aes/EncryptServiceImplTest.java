package com.algorithms.crypto.aes;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.FileInputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.util.Base64Util;
import org.junit.Before;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.util.ResourceUtils;

@RunWith(SpringJUnit4ClassRunner.class)
public class EncryptServiceImplTest {

    @InjectMocks
    EncryptServiceImpl EncryptServiceImpl;
    private File file;
    private String keyText = "E312F4F66929D72F09981BDD47D63E7805C99281C51804F1EC239283F3F2A882";

    //salt=554EAC0ADA418EB9
    //        key=E312F4F66929D72F09981BDD47D63E78
    //        iv =4EA5319DA5C50E46589216476E528113
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void whenEncryptingIntoFile_andDecryptingFileAgain_thenOriginalStringIsReturned() throws Exception {
        String originalContent = "foobar";
        file = ResourceUtils.getFile("classpath:certs/aes/aes.key");
    
        byte[] key = javax.xml.bind.DatatypeConverter.parseHexBinary(keyText);
        byte[] hex = Hex.decodeHex(keyText.toCharArray());
        SecretKey secretKey = new SecretKeySpec(hex,  "AES");

        int maxKeyLen = Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("MaxAllowedKeyLength=[" + maxKeyLen + "].");
        
        FileEncrypterDecrypter fileEncrypterDecrypter = new FileEncrypterDecrypter(secretKey, "AES/CBC/PKCS5Padding");
        fileEncrypterDecrypter.encrypt(originalContent, "baz.enc");

        String decryptedContent = fileEncrypterDecrypter.decrypt("baz.enc");
        assertThat(decryptedContent, is(originalContent));

        new File("baz.enc").delete(); // cleanup
    }
}
