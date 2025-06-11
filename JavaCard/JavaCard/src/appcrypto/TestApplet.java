package appcrypto;

import java.applet.Applet;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

// took 7 hours (setup + 6f 00 error)
// java -jar gp.jar --deletedeps --delete 0102030405
// java -jar gp.jar --install applet.cap --default -> CAP loaded

public class TestApplet extends Applet {
    private KeyPair keypair;
    private RSAPublicKey pub;
    private RSAPrivateCrtKey privKey;
    private Cipher rsa;
    private static final short KEY_SIZE = KeyBuilder.LENGTH_RSA_2048;
    private boolean keyPairGenerated = false;  //key pair has been generated
    private RandomData randomData;

    public static void install(byte[] ba, short offset, byte len) {
        (new TestApplet()).register();
    }

    protected TestApplet() {
        keypair = new KeyPair(KeyPair.ALG_RSA_CRT, KEY_SIZE); // initialize the RSA key (2048-bit)
        rsa = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false); 
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register();
    }

    // PKCS#1 v1.5 padding function
    private void pkcs1Pad(byte[] message, short messageOffset, short messageLen, 
                         byte[] paddedMessage, short paddedOffset, short modulusLen) {
        short i = paddedOffset;
        
        paddedMessage[i++] = 0x00;  // Start with 0x00
        paddedMessage[i++] = 0x02;  // Padding type (0x02)

        // Adding random padding bytes (not 0x00)
        short paddingLen = (short)(modulusLen - messageLen - 3);
        byte[] randomBytes = new byte[1];
        for (short j = 0; j < paddingLen; j++) {
            do {
                randomData.generateData(randomBytes, (short)0, (short)1);
            } while (randomBytes[0] == 0x00);
            paddedMessage[i++] = randomBytes[0];
        }

        paddedMessage[i++] = 0x00;  // Final 0x00 byte

        // Copy the message after padding
        System.arraycopy(message, messageOffset, paddedMessage, i, messageLen);
    }

    // Remove PKCS#1 padding after decryption
    private short removePkcs1Padding(byte[] decryptedMessage, short offset, short length) {
        // Ensure the padding is valid
        if (decryptedMessage[offset] != 0x00 || decryptedMessage[(short)(offset + 1)] != 0x02) {
            ISOException.throwIt((short) 0x9106);  // Error: Invalid padding
        }

        // Find the end of padding
        short i = (short)(offset + 2);
        while (decryptedMessage[i] != 0x00) {
            i++;
            if (i >= (short)(offset + length)) {
                ISOException.throwIt((short) 0x9106);  // Error: Invalid padding
            }
        }

        // Return the length of the actual message
        return (short)(length - (i - offset) - 1);
    }

    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        
        switch (buf[ISO7816.OFFSET_INS]) {
            case (0x02):  // Generate RSA keypair
                if (!keyPairGenerated) {  // Ensure the keypair is generated only once
                    keypair.genKeyPair();
                    privKey = (RSAPrivateCrtKey) keypair.getPrivate();
                    pub = (RSAPublicKey) keypair.getPublic();
                    keyPairGenerated = true;  // Mark keypair as generated
                }
                return;

            case (0x04): // Get exponent (public key)
                short expLen = pub.getExponent(buf, (short) 0);
                apdu.setOutgoing();
                apdu.setOutgoingLength(expLen);
                apdu.sendBytes((short) 0, expLen);
                return;

            case (0x06): // Get modulus (public key)
                short modLen = pub.getModulus(buf, (short) 0);
                apdu.setOutgoing();
                apdu.setOutgoingLength(modLen);
                apdu.sendBytes((short) 0, modLen);
                return;

            case (0x08):  // Decrypt ciphertext
                short bytesRead = apdu.setIncomingAndReceive();
                short totalLen = apdu.getIncomingLength();
                // Check if keys are initialized
                if (privKey == null || rsa == null) {
                    ISOException.throwIt((short) 0x9102);  // Error: no key or cipher
                }
                // Initialize cipher in decryption mode
                rsa.init(privKey, Cipher.MODE_DECRYPT);
                // Decrypt the ciphertext
                short outLen = rsa.doFinal(buf, ISO7816.OFFSET_CDATA, totalLen, buf, (short) 0);
                // Remove PKCS#1 padding and get actual message length
                short messageLen = removePkcs1Padding(buf, (short)0, outLen);
                // Move the actual message to the beginning of the buffer
                System.arraycopy(buf, (short)(outLen - messageLen), buf, (short)0, messageLen);

                // Send back the decrypted message
                apdu.setOutgoing();
                apdu.setOutgoingLength(messageLen);
                apdu.sendBytes((short) 0, messageLen);
                return;

            case (0x10):  // Encrypt message (using public key)
                short bytesToEncrypt = apdu.setIncomingAndReceive();
                short messageLen = apdu.getIncomingLength();

                // Check if public key is available
                if (pub == null) {
                    ISOException.throwIt((short) 0x9105);  // Error: no public key
                }

                // Calculate the length of the modulus in bytes
                short modulusLen = (short)((pub.getModulusLength() + 7) / 8);

                // Create a temporary buffer for the padded message
                byte[] paddedMessage = new byte[modulusLen];
                
                // Pad the message
                pkcs1Pad(buf, ISO7816.OFFSET_CDATA, messageLen, paddedMessage, (short)0, modulusLen);
                
                // Initialize cipher in encryption mode
                rsa.init(pub, Cipher.MODE_ENCRYPT);
                
                // Encrypt the padded message
                short encryptedLen = rsa.doFinal(paddedMessage, (short)0, modulusLen, buf, (short)0);

                // Send the encrypted message
                apdu.setOutgoing();
                apdu.setOutgoingLength(encryptedLen);
                apdu.sendBytes((short) 0, encryptedLen);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
