import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Cliente {
    private static final long TIEMPO_ENTRE_MENSAJES = 3000; // 3 segundos de espera para evitar spam

    public static void main(String[] args) {
        try {
            // Establecer una conexión con el servidor
            Socket socket = new Socket("192.168.123.1",6969);
            PrintWriter escritor = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader lector = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedReader lectorConsola = new BufferedReader(new InputStreamReader(System.in));

            // Recibir y mostrar el nombre de usuario asignado
            String nombreUsuario = lector.readLine();
            System.out.println("¡Bienvenido, " + nombreUsuario + "!");

            // Hilo para recibir mensajes del servidor
            Thread hiloRecibirMensajes = new Thread(() -> {
                try {
                    String mensaje;
                    while ((mensaje = lector.readLine()) != null) {
                        System.out.println("Mensaje del servidor: " + mensaje);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            hiloRecibirMensajes.start();

            // Hilo para enviar mensajes al servidor
            Thread hiloEnviarMensajes = new Thread(() -> {
                try {
                    String usuario;
                    String mensajeUsuario;
                    while ((mensajeUsuario = lectorConsola.readLine()) != null) {
                        escritor.println(mensajeUsuario);
                        Thread.sleep(TIEMPO_ENTRE_MENSAJES); // Esperar para evitar enviar mensajes muy rápido
                    }
                } catch (IOException | InterruptedException e) {
                    e.printStackTrace();
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
        }
    }
}