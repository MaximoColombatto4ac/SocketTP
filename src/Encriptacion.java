import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Encriptacion {
    public final static String delimitador = "EsteEsUnCaracterDelimitador";
    public final static String delimitadorCodificado = Base64.getEncoder().encodeToString(delimitador.getBytes());
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
        return publicKey2;
    }

    public static void enviarClavePublica(byte[] publicKey, DataOutputStream escritor) throws IOException {
        escritor.writeInt(publicKey.length);
        escritor.write(publicKey);
    }
    public static String hashearMensaje(String mensaje) throws Exception {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(mensaje.getBytes(StandardCharsets.UTF_8));
            return new String(hash, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new Exception("Error al hashear el mensaje", e);
        }
    }
    public static String descifrarMensaje(String llegada, Cipher c, Cipher c2) throws Exception {

            String[] mensajeMasFirma = llegada.split(Encriptacion.delimitadorCodificado);

            String mensaje = new String(c2.doFinal(mensajeMasFirma[0].getBytes()));
            String firma = new String(c.doFinal(mensajeMasFirma[1].getBytes()));
            if (!Encriptacion.hashearMensaje(mensaje).equals(firma)){
                throw new Exception("modoficacion!!");
            }else {
                return mensaje;
            }
    }
}