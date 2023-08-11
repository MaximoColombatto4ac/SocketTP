package cliente;

import java.net.*;
import java.io.*;
import java.util.Scanner;

public class Client {

    public static void main(String[] args) throws IOException {

        String host = "127.0.0.1";
        int port = 5000;
        String outMsg, inMsg;
        Scanner typedInput = new Scanner(System.in);


            Socket clientSocket = new Socket(host, port);
            DataInputStream in = new DataInputStream(clientSocket.getInputStream());
            DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream());

            while (true) {
                System.out.println("\n\tType in a message: ");
                outMsg = typedInput.nextLine();

                if("<exit>".equals(outMsg)){
                    clientSocket.close();
                    System.exit(1);
                }

                out.writeUTF(outMsg);

                String receivedData = in.readUTF();
                System.out.println("Server's response:" + receivedData);
        }
    }
}
