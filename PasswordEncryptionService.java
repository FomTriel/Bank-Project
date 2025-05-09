// PasswordEncryptionService.java

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordEncryptionService {

    /** Generate an 8-byte random salt */
    public static byte[] generateSalt() {
        byte[] salt = new byte[8];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    public static byte[] getEncryptedPassword(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return f.generateSecret(spec).getEncoded();
    }

    /** Verify that an attempted password matches the given hash+salt */
    public static boolean authenticate(String attemptedPassword, byte[] encryptedPassword, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] attemptHash = getEncryptedPassword(attemptedPassword, salt);
        if (attemptHash.length != encryptedPassword.length) return false;
        for (int i = 0; i < attemptHash.length; i++) {
            if (attemptHash[i] != encryptedPassword[i]) return false;
        }
        return true;
    }
}
