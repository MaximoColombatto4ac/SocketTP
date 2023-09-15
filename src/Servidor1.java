import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Servidor1 {
    private ServerSocket servidorSocket;
    private static List<ClienteHandler> listaClientes;
    private RSA pairKeys;

    public Servidor1() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        this.pairKeys = Encriptacion.generarClaves();
    }

    public RSA getPairKeys() {
        return pairKeys;
    }

    public void setPairKeys(RSA pairKeys) {
        this.pairKeys = pairKeys;
    }

    public static void main(String[] args) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        Servidor1 servidor = new Servidor1();
        servidor.iniciar();
    }

    public void iniciar() {
        try {
            // Inicializa el servidor y establece el número de puerto en el que escuchará conexiones
            servidorSocket = new ServerSocket(6969);
            System.out.println("Servidor iniciado. Esperando conexiones...");

            // Lista para almacenar los manejadores de clientes conectados
            listaClientes = new ArrayList<>();

            while (true) {
                // Acepta una nueva conexión de cliente
                Socket socketCliente = servidorSocket.accept();
                System.out.println("Nueva conexión aceptada");

                // Crea un manejador de cliente para manejar las interacciones con este cliente
                ClienteHandler clienteHandler = new ClienteHandler(socketCliente);


                //enviamos clave publica
                DataOutputStream dOut = new DataOutputStream(socketCliente.getOutputStream());
                Encriptacion.enviarClavePublica(pairKeys.PublicKey.getEncoded(),dOut);



                listaClientes.add(clienteHandler);
                clienteHandler.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } finally {
            // Cierra el socket del servidor al finalizar
            if (servidorSocket != null) {
                try {
                    servidorSocket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }


    private class ClienteHandler extends Thread {
        private Socket socketCliente;
        private PrintWriter escritor;
        private BufferedReader lector;
        private String nombreUsuario;
        public PublicKey claveCLiente;

        public ClienteHandler(Socket socket) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            socketCliente = socket;
            claveCLiente = setearClave();
        }
        public PublicKey setearClave() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            DataInputStream dIn = new DataInputStream(socketCliente.getInputStream());
            return Encriptacion.recibirCLavePublica(dIn);
        }

        public void run() {
            try {

                Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                Cipher c2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");

                c2.init(Cipher.DECRYPT_MODE, Servidor1.this.pairKeys.PrivateKey);
                c.init(Cipher.DECRYPT_MODE, claveCLiente);

                // Establece flujos de entrada y salida para la comunicación con el cliente
                escritor = new PrintWriter(socketCliente.getOutputStream(), true);
                lector = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));

                // Solicita al cliente que ingrese su nombre de usuario
                escritor.println("Ingresa tu nombre de usuario:");
                nombreUsuario = lector.readLine();
                nombreUsuario = Encriptacion.descifrarMensaje(nombreUsuario,c,c2);
                System.out.println("Nuevo usuario conectado: " + nombreUsuario);

                escritor.println("elija un usuario:");

                for (ClienteHandler cliente : Servidor1.this.listaClientes) {
                    if (!cliente.nombreUsuario.equals(this.nombreUsuario)) {
                        escritor.println(cliente.nombreUsuario);
                    }
                }


                String usuario = lector.readLine();
                usuario = Encriptacion.descifrarMensaje(usuario,c,c2);

                String llegada;
                while ((llegada = lector.readLine()) != null ) {

                    String mensaje = Encriptacion.descifrarMensaje(llegada, c, c2);
                        for (ClienteHandler cliente : listaClientes) {
                            if (cliente.nombreUsuario.equals(usuario)) {

                                c2.init(Cipher.ENCRYPT_MODE, cliente.claveCLiente);
                                c.init(Cipher.ENCRYPT_MODE, Servidor1.this.pairKeys.PrivateKey);

                                byte[] mensajeCifrado = c.doFinal(mensaje.getBytes());
                                byte[] firmaByte = c2.doFinal(Encriptacion.hashearMensaje(mensaje).getBytes());

                                mensaje = new String(mensajeCifrado);
                                String firma = new String(firmaByte);

                                cliente.escritor.print(mensaje + Encriptacion.delimitadorCodificado + firma + Encriptacion.delimitadorCodificado + nombreUsuario);
                            }
                        }
                }

                // Usuario desconectado, realiza limpieza y elimina de la lista
                System.out.println("Usuario desconectado: " + nombreUsuario);
                listaClientes.remove(this);
                socketCliente.close();
            } catch (IOException e) {
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
            } finally {
                // Cierra los flujos de entrada y salida al finalizar
                if (escritor != null) {
                    escritor.close();
                }
                try {
                    if (lector != null) {
                        lector.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }
}