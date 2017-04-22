import java.io.*;
import java.net.Socket;
import java.security.cert.*;
import java.util.Base64;

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

    String certToString(Certificate c) throws CertificateEncodingException {
        String LINE_SEPERATOR = System.getProperty("line.separator");
        final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPERATOR.getBytes());
        final byte[] rawCrtText = c.getEncoded();
        final String encodedCertText = new String(encoder.encode(rawCrtText));
        return encodedCertText;
    }

    X509Certificate stringToCert(String c) throws CertificateException {
        final Base64.Decoder decoder = Base64.getMimeDecoder();
        byte[] decoded = decoder.decode(c);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Certificate nxCert = cf.generateCertificate(new ByteArrayInputStream(decoded));
        return (X509Certificate) nxCert;
    }


}
