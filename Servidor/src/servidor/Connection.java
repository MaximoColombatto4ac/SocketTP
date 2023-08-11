package servidor;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

public class Connection extends Thread {

    DataInputStream in;
    DataOutputStream out;
    Socket clientSocket;

    public Connection(Socket clientSocket){
        try {
            this.clientSocket = clientSocket;
            in = new DataInputStream(this.clientSocket.getInputStream());
            out = new DataOutputStream(this.clientSocket.getOutputStream());
        }
        catch (IOException e) {
            System.err.print("Connection: " + e.getMessage());
        }
    }

    public void run(){
        try {
            while (true) {

                String data = in.readUTF();
                String response = "hola";

                System.out.println(data);

                out.writeUTF(response);

            }
        }
        catch (Exception e) {
            System.out.println("The connection with one client program was interrupted");
        }
    }
}
