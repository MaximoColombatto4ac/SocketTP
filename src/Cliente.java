import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Cliente {
    private static final long TIEMPO_ENTRE_MENSAJES = 15; // 3 segundos de espera para evitar spam
    private RSA pairKeys;
    private PublicKey claveServidor;
    private Key claveSimetrica;


    public Cliente() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        this.pairKeys = Encriptacion.generarClaves();
        this.claveServidor = null;
        this.claveSimetrica = null;
    }

    public Key getClaveSimetrica() {
        return claveSimetrica;
    }

    public void setClaveSimetrica(Key claveSimetrica) {
        this.claveSimetrica = claveSimetrica;
    }

    public PublicKey getClaveServidor() {
        return claveServidor;
    }

    public void setClaveServidor(PublicKey claveServidor) {
        this.claveServidor = claveServidor;
    }

    public RSA getPairKeys() {
        return pairKeys;
    }

    public void setPairKeys(RSA pairKeys) {
        this.pairKeys = pairKeys;
    }

    public static void main(String[] args) {
        try {

            // Establecer una conexión con el servidor
            Socket socket = new Socket("192.168.123.1", 6969);



            PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedReader lectorConsola = new BufferedReader(new InputStreamReader(System.in));

            //creamos la clase para guardar las claves
            Cliente cliente = new Cliente();

            //enviamos
            DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());
            Encriptacion.enviarClavePublica(cliente.pairKeys.PublicKey.getEncoded(),dOut);


            //recibimos la clave publica del servidor
            DataInputStream dIn = new DataInputStream(socket.getInputStream());
            cliente.setClaveServidor(Encriptacion.recibirCLavePublica(dIn));

            //recibimos clave simetrica
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(cliente.getClaveServidor());
            Cipher desencriptador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            desencriptador.init(Cipher.DECRYPT_MODE, cliente.pairKeys.PrivateKey);
            String claveSimetrica = lector.readLine();
            byte[] claveS = Encriptacion.recibirClaveSimetrica(claveSimetrica,publicSignature,desencriptador);
            Key aeskey = new SecretKeySpec(claveS,"AES");
            cliente.setClaveSimetrica(aeskey);




            // Hilo para recibir mensajes del servidor
            Thread hiloRecibirMensajes = new Thread(() -> {
                try {
                    String llegada;
                    while ((llegada = lector.readLine()) != null) {
                            String mensaje = Encriptacion.descifrarMensaje(llegada,desencriptador,publicSignature);
                            System.out.println(mensaje);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            hiloRecibirMensajes.start();

            // Hilo para enviar mensajes al servidor
            Thread hiloEnviarMensajes = new Thread(() -> {
                try {

                    Signature privateSignature = Signature.getInstance("SHA256withRSA");
                    privateSignature.initSign(cliente.pairKeys.PrivateKey);

                    String mensajeUsuario;
                    while ((mensajeUsuario = lectorConsola.readLine()) != null) {
                        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        c.init(Cipher.ENCRYPT_MODE, cliente.claveServidor);

                        escritor.println(Encriptacion.encriptarMensaje(c,privateSignature,mensajeUsuario));

                        Thread.sleep(TIEMPO_ENTRE_MENSAJES); // Esperar para evitar enviar mensajes muy rápido
                    }
                } catch (IOException | InterruptedException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e);
                } catch (IllegalBlockSizeException e) {
                    throw new RuntimeException(e);
                } catch (BadPaddingException e) {
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            hiloEnviarMensajes.start();

            // Esperar a que ambos hilos terminen antes de cerrar los recursos
            hiloRecibirMensajes.join();
            hiloEnviarMensajes.join();

            // Cerrar los recursos utilizados
            escritor.close();
            lector.close();
            lectorConsola.close();
            socket.close();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


}