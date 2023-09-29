import javax.crypto.*;
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
    public static RSA generarClavesAsimetricas() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException {
        RSA rsa = new RSA();
        rsa.genKeyPair(512);
        return rsa;
    }
    public static SecretKey generarClaveSimetrica() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
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
    public static void enviarClaveSimetrica(SecretKey key, DataOutputStream escritor,Cipher c,Signature s) throws IllegalBlockSizeException, BadPaddingException, SignatureException, IOException {
        byte[] mensajeCifrado = c.doFinal(key.getEncoded());
        s.update(key.getEncoded());
        byte[] firma = s.sign();
        String encript = new String(Base64.getEncoder().encode(mensajeCifrado)) + Encriptacion.delimitadorCodificado + new String(Base64.getEncoder().encode(firma));
        escritor.writeUTF(encript);
    }






    public static void recibirClaveSimetrica(DataInputStream dIn,PrivateKey pv, Signature s, Cipher c) throws Exception {
        String llegada = dIn.readUTF();
        String[] mensajeMasFirma = llegada.split(Encriptacion.delimitadorCodificado);
        byte[] mensaje = c.doFinal(Base64.getDecoder().decode(mensajeMasFirma[0].getBytes()));

        s.update(mensajeMasFirma[0].getBytes());
        if (!s.verify(Base64.getDecoder().decode(mensajeMasFirma[1].getBytes()))){

        }else {
            throw new Exception("modificacion!!");
        }
    }

    public static String descifrarMensaje(String llegada, PrivateKey pv, Signature sig1) throws Exception {
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.DECRYPT_MODE, pv);
            String[] mensajeMasFirma = llegada.split(Encriptacion.delimitadorCodificado);
            sig1.update(mensajeMasFirma[0].getBytes());
            String mensaje = new String(c.doFinal(Base64.getDecoder().decode(mensajeMasFirma[0].getBytes())));
            if (sig1.verify(Base64.getDecoder().decode(mensajeMasFirma[1].getBytes()))){
                throw new Exception("modificacion!!");
            }else {
                return mensaje;
            }
    }
    public static String encriptarMensaje(Cipher c, Signature s, String llegada) throws IllegalBlockSizeException, BadPaddingException, SignatureException {
        byte[] mensajeCifrado = c.doFinal(llegada.getBytes());
        s.update(llegada.getBytes(StandardCharsets.UTF_8));
        byte[] firma = s.sign();
        String encript = new String(Base64.getEncoder().encode(mensajeCifrado)) + Encriptacion.delimitadorCodificado + new String(Base64.getEncoder().encode(firma));
        return encript;
    }
}