import static org.junit.Assert.*;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class UnitTest {

    /**
     * 1) Salt length: generateSalt() must return 8 bytes
     */
    @Test
    public void testGenerateSaltLength() throws NoSuchAlgorithmException {
        byte[] salt = PasswordEncryptionService.generateSalt();
        assertNotNull("Salt should not be null", salt);
        assertEquals("Salt should be 8 bytes long", 8, salt.length);
    }

    /**
     * 2) ensuring that the same password + same salt gives same hash
     */
    @Test
    public void testPasswordEncryptionSaltHashMatch() 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt  = PasswordEncryptionService.generateSalt();
        byte[] hash1 = PasswordEncryptionService.getEncryptedPassword("password123", salt);
        byte[] hash2 = PasswordEncryptionService.getEncryptedPassword("password123", salt);
        assertArrayEquals("Hashes for same password and salt should match", hash1, hash2);
    }

    /**
     * 3) Unique-per-salt hashing: same password + different salts → different hashes
     */
    @Test
    public void testPasswordEncryptionUniquePerSalt() 
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String pass  = "password123";
        byte[] salt1 = PasswordEncryptionService.generateSalt();
        byte[] salt2 = PasswordEncryptionService.generateSalt();
        byte[] hash1 = PasswordEncryptionService.getEncryptedPassword(pass, salt1);
        byte[] hash2 = PasswordEncryptionService.getEncryptedPassword(pass, salt2);
        assertFalse("Hashes with different salts should differ", Arrays.equals(hash1, hash2));
    }

    /**
     * 4) checks that balance starts at 0 after account creation
     */
    @Test
    public void testAccountInitialBalance() {
        Account acc = new Account("testuser", new byte[8], new byte[8]);
        assertEquals("New account should start with zero balance", 0.0, acc.getBalance(), 0.0001);
    }
}
