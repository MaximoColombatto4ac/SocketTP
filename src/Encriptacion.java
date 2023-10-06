import javax.crypto.*;
import java.io.*;
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
    public static SecretKey generarClaveSimetrica() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }
    public static String enviarClaveSimetrica(SecretKey key, Cipher c, Signature s) throws IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
        byte[] mensajeCifrado = c.doFinal(key.getEncoded());
        s.update(key.getEncoded());
        byte[] firma = s.sign();
        String encript = new String(Base64.getEncoder().encode(mensajeCifrado)) + Encriptacion.delimitadorCodificado + new String(Base64.getEncoder().encode(firma));
        return encript;
    }
    public static byte[] recibirClaveSimetrica(String llegada, Signature sig1, Cipher c) throws Exception {
        String[] mensajeMasFirma = llegada.split(Encriptacion.delimitadorCodificado);
        byte[] mensaje = c.doFinal(Base64.getDecoder().decode(mensajeMasFirma[0]));
        sig1.update(mensaje);
        if (sig1.verify(Base64.getDecoder().decode(mensajeMasFirma[1]))){
            return mensaje;
        }else {
            throw new Exception("modificacion!!");
        }
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