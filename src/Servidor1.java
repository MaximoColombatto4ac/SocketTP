import javax.crypto.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;


public class Servidor1 {
    private ServerSocket servidorSocket;
    private static List<ClienteHandler> listaClientes;
    private RSA pairKeys;
    public SecretKey key;

    public Servidor1() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        this.pairKeys = Encriptacion.generarClavesAsimetricas();
        this.key = Encriptacion.generarClaveSimetrica();
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

                DataOutputStream dOut = new DataOutputStream(socketCliente.getOutputStream());

                Signature privateSignature = Signature.getInstance("SHA256withRSA");
                privateSignature.initSign(Servidor1.this.pairKeys.PrivateKey);

                //enviamos clave publica
                Encriptacion.enviarClavePublica(pairKeys.PublicKey.getEncoded(),dOut);

                //enviamos clave simetrica
                Cipher encriptador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                encriptador.init(Cipher.ENCRYPT_MODE, clienteHandler.claveCLiente);
                Encriptacion.enviarClaveSimetrica(key,dOut,encriptador,privateSignature);


                listaClientes.add(clienteHandler);
                clienteHandler.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
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

                Cipher c2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                c2.init(Cipher.ENCRYPT_MODE, claveCLiente);
                Cipher c3 = Cipher.getInstance("RSA/ECB/PKCS1Padding");

                Signature publicSignature = Signature.getInstance("SHA256withRSA");
                publicSignature.initVerify(claveCLiente);

                Signature privateSignature = Signature.getInstance("SHA256withRSA");
                privateSignature.initSign(Servidor1.this.pairKeys.PrivateKey);





                // Establece flujos de entrada y salida para la comunicación con el cliente
                escritor = new PrintWriter(socketCliente.getOutputStream(), true);
                lector = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));


                String mens = "";


                // Solicita al cliente que ingrese su nombre de usuario
                escritor.println(Encriptacion.encriptarMensaje(c2, privateSignature,"Ingresa tu nombre de usuario:"));
                nombreUsuario = lector.readLine();
                nombreUsuario = Encriptacion.descifrarMensaje(nombreUsuario,Servidor1.this.pairKeys.PrivateKey,publicSignature);
                System.out.println("Nuevo usuario conectado: " + nombreUsuario);

                escritor.println(Encriptacion.encriptarMensaje(c2, privateSignature,"elija un usuario:"));

                for (ClienteHandler cliente : Servidor1.this.listaClientes) {
                    if (!cliente.nombreUsuario.equals(this.nombreUsuario)) {
                        escritor.println(cliente.nombreUsuario);
                    }
                }
                String usuario = lector.readLine();
                usuario = Encriptacion.descifrarMensaje(usuario,Servidor1.this.pairKeys.PrivateKey,publicSignature);
                mens = "chat con: " + usuario;
                escritor.println(Encriptacion.encriptarMensaje(c2, privateSignature,mens));





                String llegada;
                while ((llegada = lector.readLine()) != null ) {
                    String mensaje = Encriptacion.descifrarMensaje(llegada,Servidor1.this.pairKeys.PrivateKey,publicSignature);
                    System.out.println(mensaje);
                        for (ClienteHandler cliente : listaClientes) {

                            if (cliente.nombreUsuario.equals(usuario)) {
                                c3.init(Cipher.ENCRYPT_MODE, cliente.claveCLiente);
                                cliente.escritor.println(Encriptacion.encriptarMensaje(c2,privateSignature, mensaje));
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