import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Cliente {
    private static final long TIEMPO_ENTRE_MENSAJES = 3000; // 3 segundos de espera para evitar spam
    private RSA pairKeys;

    public PublicKey claveServidor;

    public Cliente() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        this.pairKeys = Encriptacion.generarClaves();
        this.claveServidor = null;
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


            // Hilo para recibir mensajes del servidor
            Thread hiloRecibirMensajes = new Thread(() -> {
                try {

                    Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    Cipher c2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");

                    c2.init(Cipher.DECRYPT_MODE, cliente.pairKeys.PrivateKey);
                    c.init(Cipher.DECRYPT_MODE, cliente.claveServidor);

                    String llegada;

                    while ((llegada = lector.readLine()) != null) {

                        String[] mensajeMasFirma = llegada.split(Encriptacion.delimitadorCodificado);

                      /*  String mensaje = new String(c2.doFinal(mensajeMasFirma[0].getBytes()));
                        String firma = new String(c.doFinal(mensajeMasFirma[1].getBytes()));
                        String nombreOrigen = mensajeMasFirma[2];*/

                      /*  if (Encriptacion.hashearMensaje(mensaje).equals(firma)){*/
                            System.out.println(mensajeMasFirma[0]);
                        /*}*/

                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
            hiloRecibirMensajes.start();

            // Hilo para enviar mensajes al servidor
            Thread hiloEnviarMensajes = new Thread(() -> {
                try {
                    Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    Cipher c2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");

                    c2.init(Cipher.ENCRYPT_MODE, cliente.pairKeys.PrivateKey);
                    c.init(Cipher.ENCRYPT_MODE, cliente.claveServidor);

                    String mensajeUsuario;
                    String firmaString;

                    while ((mensajeUsuario = lectorConsola.readLine()) != null) {

                        byte[] mensajeCifrado = c.doFinal(mensajeUsuario.getBytes());

                        byte[] firma = c2.doFinal(Encriptacion.hashearMensaje(mensajeUsuario).getBytes());

                        firmaString = new String(firma);
                        mensajeUsuario = new String(mensajeCifrado);

                        escritor.println(mensajeUsuario + Encriptacion.delimitadorCodificado + firmaString);

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
        }
    }


}