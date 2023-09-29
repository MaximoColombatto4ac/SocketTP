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
    public static String descifrarMensaje(String llegada, Cipher c, Signature sig1) throws Exception {
            String[] mensajeMasFirma = llegada.split(Encriptacion.delimitadorCodificado);
            String mensaje = new String(c.doFinal(Base64.getDecoder().decode(mensajeMasFirma[0].getBytes())));
            sig1.update(mensaje.getBytes());
            if (sig1.verify(Base64.getDecoder().decode(mensajeMasFirma[1].getBytes()))){
                return mensaje;
            }else {
                throw new Exception("modificacion!!");
            }
    }
    public static String encriptarMensaje(Cipher c, Signature s, String llegada) throws IllegalBlockSizeException, BadPaddingException, SignatureException {
        byte[] mensajeCifrado = c.doFinal(llegada.getBytes());
        s.update(llegada.getBytes());
        byte[] firma = s.sign();
        String encript = new String(Base64.getEncoder().encode(mensajeCifrado)) + Encriptacion.delimitadorCodificado + new String(Base64.getEncoder().encode(firma));
        return encript;
    }
}