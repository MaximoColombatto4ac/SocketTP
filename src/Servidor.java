import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class Servidor {
    private ServerSocket servidorSocket;
    private static List<ClienteHandler> listaClientes;

    public static void main(String[] args) {
        Servidor servidor = new Servidor();
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
                listaClientes.add(clienteHandler);
                clienteHandler.start();
            }
        } catch (IOException e) {
            e.printStackTrace();
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

        public ClienteHandler(Socket socket) {
            socketCliente = socket;
        }

        public void run() {
            try {
                // Establece flujos de entrada y salida para la comunicación con el cliente
                escritor = new PrintWriter(socketCliente.getOutputStream(), true);
                lector = new BufferedReader(new InputStreamReader(socketCliente.getInputStream()));

                // Solicita al cliente que ingrese su nombre de usuario
                escritor.println("Ingresa tu nombre de usuario:");
                nombreUsuario = lector.readLine();
                System.out.println("Nuevo usuario conectado: " + nombreUsuario);

                escritor.println("elija un usuario:");

                for (ClienteHandler cliente: Servidor.this.listaClientes) {
                    if (!cliente.nombreUsuario.equals(this.nombreUsuario)){
                        escritor.println(cliente.nombreUsuario);
                    }
                }

                String usuario = lector.readLine();
                String mensaje;

                while ((mensaje = lector.readLine()) != null) {
                    for (ClienteHandler cliente : Servidor.this.listaClientes) {
                        if (cliente.nombreUsuario.equals(usuario)) {
                            cliente.enviarMensaje(nombreUsuario + ": " + mensaje);
                        }
                    }
                }

                // Usuario desconectado, realiza limpieza y elimina de la lista
                System.out.println("Usuario desconectado: " + nombreUsuario);
                listaClientes.remove(this);
                socketCliente.close();
            } catch (IOException e) {
                e.printStackTrace();
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

        // Método para enviar un mensaje al cliente
        public void enviarMensaje(String mensaje) {
            escritor.println(mensaje);
        }
    }
}
