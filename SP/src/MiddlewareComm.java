import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

/**
 * Created by Nassim on 20/04/2017.
 */
public class MiddlewareComm {
    static int MiddlewarePort =2234;

    boolean sendCert(String ip, String cert){
        Socket clientSocket = null;
        try {
            clientSocket = new Socket(ip, MiddlewarePort);
            DataOutputStream outToServer = new DataOutputStream(clientSocket.getOutputStream());
            BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            outToServer.writeBytes(cert + '\n');
            String Response  = inFromServer.readLine();
            System.out.println("Middleware Response:" + Response);
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

}
