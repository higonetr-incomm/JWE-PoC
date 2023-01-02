import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PoCJWEApplication {
    public static String aesKek = "d3c6339972ae45c2ab33aa3002573c12";
    public static String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp8YRb5Hpys44iDW7VbBu\n" +
            "rjGgswpAvW+eGA9EDQaNwK4jR9E1nv66gfpRWl/VFy9s10qqVSTN3H0UEO/W/ujV\n" +
            "FJRhsVWFgsBIcuiwlRFeYhl/Sn70V+28VI6wiO/MXkglrlH90cuidzFznfWmK6lA\n" +
            "U4ocFyqMvMZzGf/fe+Heh8kEt9ggL12YXfL3AmTShSTBpgp6+tvIQP/6SzIMnOIl\n" +
            "0/aP00TgCn7y9TRVPTr1SZuP+NIeQbhbsRHld32uZ5x8FqkiDyIxfDilosUFVCGj\n" +
            "l6migMJ+yS35rC3vtEPVIwacVY5Y+MDjYT4aaFA/hRO3G92MqwoOlRpEL+vzEh3C\n" +
            "kQIDAQAB\n" +
            "-----END PUBLIC KEY-----";
    public static String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnxhFvkenKzjiI\n" +
            "NbtVsG6uMaCzCkC9b54YD0QNBo3AriNH0TWe/rqB+lFaX9UXL2zXSqpVJM3cfRQQ\n" +
            "79b+6NUUlGGxVYWCwEhy6LCVEV5iGX9KfvRX7bxUjrCI78xeSCWuUf3Ry6J3MXOd\n" +
            "9aYrqUBTihwXKoy8xnMZ/9974d6HyQS32CAvXZhd8vcCZNKFJMGmCnr628hA//pL\n" +
            "Mgyc4iXT9o/TROAKfvL1NFU9OvVJm4/40h5BuFuxEeV3fa5nnHwWqSIPIjF8OKWi\n" +
            "xQVUIaOXqaKAwn7JLfmsLe+0Q9UjBpxVjlj4wONhPhpoUD+FE7cb3YyrCg6VGkQv\n" +
            "6/MSHcKRAgMBAAECggEAFdpyXfaDHfQToAZjsusq14zGUlvlB+fYj2i5o/q1DyJ/\n" +
            "nPSux9mFQLXyz9NIxd7bDgX/Ptzu5afzK6uZ9RUt4CLdwMQTgm76YOFXUutywFNy\n" +
            "5ai4uhVQ4TC+5O9bTvKV2el7Js8gB+eMmEgtj2VZ6CfGtevIbjRpPLs8CH5oxoXd\n" +
            "xe1UU65MIeFUmUTJbP5Dr9/5yJyZzdxTGv7NfyBX/KwjVv/MPTmEamr2/J33VivH\n" +
            "EuAGKEoGEQ7hV/BwTjHsEAeZadHZNIEiom+K8mCoxEZVXU29+0dvl8MTS3lF4Gg8\n" +
            "frhyKLm+ABrYKho+xwXJJYvmhXwk7N3irG40d3TWUwKBgQC6CHOSy4AFIs+mNSDb\n" +
            "Rb2MbWl/YP7AdK+jG5h/Kthb1tzffrVfX/f7IDwZFsNkIxO7xV/Jc+F2iehOy2sX\n" +
            "SVIdbHO5I/q36xEv12UV3amXaeSNURX+bkIalKETEumiBBiuMA+E/U/1x9b9Gigg\n" +
            "9ix8+4bLdJXJkTJXD4Y+v+tBZwKBgQDm35TyXMEi4yqttFF0eQk7fBV8HZ97F2rG\n" +
            "2tqg7OR25238tTXnWOt4ud0CB4UbvW5gQmh6nFKHULqHGS285nlx0HCI2/EmN6Rj\n" +
            "vS9IL+6TAr9w0Cf0/wm210tGQ71zzSlPqBVvjy8rtfT0KYNViOdP27kSOyhPeyW7\n" +
            "bO66A54JRwKBgQClnLZ+vWlnqRjgpzVr30ciR5j+i/Pek0J02zFELHlWMQ6KbHu8\n" +
            "v2u9BXJbB3fEorGDnO9sIRxbceP8mXzpyx0uEolnDY+6waqYQ5G7CI1cvSl5YPFK\n" +
            "gw+YKC7JEzIoSKtMDn8SbowLiu9qfSmyRlVOooDaiRx7yCXfeXOSUzp1CwKBgQCP\n" +
            "ssPLYi4YH9qViXFVlGxJqP7aZLm57KZaJSgFF81PsNZFfyiQ2UieuNi1haa00GAd\n" +
            "69eJ0TiQ3o9qvSI5vB4E2B7jIDpldiaMqdj/Dk5pFEHB3t2v4PnT4wcIMet+Y0j+\n" +
            "Onk1GaLbiwJu4lPLbk3C59i2XznE1rpygOfJwaygywKBgApZTcMsOz35K25ACI0A\n" +
            "lgZACL+XMtdH7wagSV9Pofk+uUdi2U7hjmkfsKOPezXnS6DxPfjGzbrusg4IBYik\n" +
            "wuf/AobZPKopYmq/HI4j1k2eVk9fNmMOnJCHHcVUHEml7Ten+uH0+iiN1ldbcxU/\n" +
            "kP01Kr7YdIv10zPYgb/s5cCm\n" +
            "-----END PRIVATE KEY-----";
    public static String eccServerPublicKey =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaTV560FEotvfEW50Wc3jV929x6S3" +
                    "Vusblq97IuCj8UAPrFowvnfMmNgCnONquWyWGk6hpU3bsxBlWF4hs3UkRA==";
    public static String eccServerPrivateKey =
            "MHcCAQEEIADYciEp6320quQtDyZd94O53IO1s8eXw9uU7az1pPDjoAoGCCqGSM49" +
                    "AwEHoUQDQgAEaTV560FEotvfEW50Wc3jV929x6S3Vusblq97IuCj8UAPrFowvnfM" +
                    "mNgCnONquWyWGk6hpU3bsxBlWF4hs3UkRA==";
    public static String eccClientPublicKey =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELxIzUKSWiGZODMjT8huXdWx0Pa32" +
                    "cKXMRYGEW7tq0OQTS3ickepVcq0gZTv51Lm6qDMjml2vkz2acrxyMDA4iA==";
    public static String eccClientPrivateKey =
            "MHcCAQEEIFo+pZyo3aCJV4jycFZKhwv/d80IJ1K+gvmwILTdu2lmoAoGCCqGSM49" +
                    "AwEHoUQDQgAELxIzUKSWiGZODMjT8huXdWx0Pa32cKXMRYGEW7tq0OQTS3ickepV" +
                    "cq0gZTv51Lm6qDMjml2vkz2acrxyMDA4iA==";

    public static void main(String[] args) throws InvalidKeyException {
        System.out.println(" -------- JWE Prof of Concept -------- ");

        // Adding BC as a security provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String samplePayload = "Messi is the greatest player of all time";
        System.out.println("Sample payload = " + samplePayload);

        // AES
        String aesJwe = encryptFieldAESKEK(samplePayload + " (AES)", aesKek.getBytes());
        System.out.println("AES JWE = " + aesJwe);
        String decryptedAesJwe = decryptJweAes(aesJwe, aesKek.getBytes());
        System.out.println("AES JWE decrypted = " + decryptedAesJwe);
        // AES

        // RSA
        String rsaJwe = encryptFieldRSA(samplePayload + " (RSA)", publicKey);
        System.out.println("RSA JWE = " + rsaJwe);
        String decryptedRsaJwe = decryptJweRsa(rsaJwe, privateKey);
        System.out.println("RSA JWE decrypted = " + decryptedRsaJwe);
        // RSA

        // ECC
        KeyPair clientKeyPair = EccCryptoTest.generateECKeys();
        KeyPair serverKeyPair = EccCryptoTest.generateECKeys();

        SecretKey serverSharedGeneratedSecret = EccCryptoTest.generateSharedSecret(serverKeyPair.getPrivate(), clientKeyPair.getPublic());

        String eccJWE = encryptFieldECC(samplePayload + " (ECC)", (ECPublicKey) clientKeyPair.getPublic(), serverSharedGeneratedSecret);
        System.out.println("ECC JWE = " + eccJWE);
        String decryptedEccJwe = decryptJweEcc(eccJWE, (ECPrivateKey) clientKeyPair.getPrivate());
        System.out.println("ECC JWE decrypted = " + decryptedEccJwe);
        // ECC
    }

    private static String decryptJweRsa(String rsaJwe, String privateKey) {
        try {
            RSAPrivateKey originalKey = generatePrivateKey(privateKey);
            JWEObject jwe = JWEObject.parse(rsaJwe);
            jwe.decrypt(new RSADecrypter(originalKey));
            return jwe.getPayload().toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String decryptJweAes(String aesJwe, byte[] keyBytes) {
        try {
            SecretKey originalKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
            JWEObject jwe = JWEObject.parse(aesJwe);
            jwe.decrypt(new AESDecrypter(originalKey));
            return jwe.getPayload().toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String encryptFieldAESKEK(String str, byte[] keyBytes) {
        try {
            SecretKey originalKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "AES");
            JWEHeader header = new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256GCM);
            Payload payload = new Payload(str);
            JWEObject jweObject = new JWEObject(header, payload);
            jweObject.encrypt(new AESEncrypter(originalKey));
            String jweCipherText = jweObject.serialize();
            return jweCipherText;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public static String encryptFieldECC(String str, ECPublicKey publicKey, SecretKey sharedSecretKey) {
        try {
            JWEHeader header = new JWEHeader(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM);
            Payload payload = new Payload(str);
            JWEObject jweObject = new JWEObject(header, payload);
            jweObject.encrypt(new ECDHEncrypter(publicKey, sharedSecretKey));
            return jweObject.serialize();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String decryptJweEcc(String eccJWE, ECPrivateKey privateKey) {
        try {
            JWEObject jwe = JWEObject.parse(eccJWE);
            jwe.decrypt(new ECDHDecrypter(privateKey));
            return jwe.getPayload().toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String encryptFieldRSA(String str, String publicKey) {
        try {
            RSAPublicKey rsaPublicKey = generatePublicKey(publicKey);
            JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512);

            Payload payload = new Payload(str);
            JWEObject jweObject = new JWEObject(header, payload);
            jweObject.encrypt(new RSAEncrypter(rsaPublicKey));
            String jweCipherText = jweObject.serialize();
            return jweCipherText;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static RSAPublicKey generatePublicKey(String publicKey) {
        publicKey = publicKey
                .replace("-----BEGIN PUBLIC KEY-----\n", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\n", "");

        try {
            byte[] encoded = Base64.decode(publicKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception e) {
            return null;
        }
    }

    private static RSAPrivateKey generatePrivateKey(String privateKey) {
        privateKey = privateKey
                .replace("-----BEGIN PRIVATE KEY-----\n", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\n", "");

        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKey));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(keySpec);
        } catch (Exception e) {
            return null;
        }
    }
}
