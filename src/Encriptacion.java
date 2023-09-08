import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Encriptacion {
    public static RSA generarClaves() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        RSA rsa = new RSA();
        rsa.genKeyPair(512);
        return rsa;
    }
    public static PublicKey recibirCLavePublica( DataInputStream dIn) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        int length = dIn.readInt();
        byte[] message = new byte[length];
        dIn.readFully(message, 0, message.length); // read the message
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(message);
        PublicKey publicKey2 = keyFactory.generatePublic(publicKeySpec);
        System.out.println(publicKey2);
        return publicKey2;
    }

    public static void enviarClavePublica(byte[] publicKey, DataOutputStream escritor) throws IOException {
        escritor.writeInt(publicKey.length);
        escritor.write(publicKey);
    }
}