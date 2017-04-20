import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Created by Nassim on 20/04/2017.
 */
@WebServlet(name = "Default")
public class Default extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String clientIp = request.getRemoteAddr();
        String[] selectedService = request.getParameterValues("serviceSelection");
        System.out.println(selectedService[0]);

        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");


        PrintWriter writer = response.getWriter();
        writer.println("<!DOCTYPE html><html>");
        writer.println("<head>");
        writer.println("<meta charset=\"UTF-8\" />");
        writer.println("<Title>Default Service Providors Demo</Title>");
        writer.println("</head>");
        writer.println("<body>");

        writer.println("<h1>Sent request for "+selectedService[0]+" </h1>");
        writer.println("</body>");
        writer.println("</html>");

        MiddlewareComm comm = new MiddlewareComm();
        comm.sendCert(clientIp,"Default "+selectedService[0]);

    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");


        try (PrintWriter writer = response.getWriter()) {
            String clientIp = request.getRemoteAddr();
            writer.println("<!DOCTYPE html><html>");
            writer.println("<head>");
            writer.println("<meta charset=\"UTF-8\" />");
            writer.println("<Title>Default Service Providors Demo</Title>");
            writer.println("</head>");
            writer.println("<body>");

            writer.println("<h1>These are the Default services.</h1>");
            writer.println("<h4>Please select a service.</h4>");
            writer.println("<Form method=\"post\">");
            writer.println("<input type=\"checkbox\" name=\"serviceSelection\" value=\"firstExample\">example 1<br>");
            writer.println("<input type=\"checkbox\" name=\"serviceSelection\" value=\"secondExample\">example 2<br>");
            writer.println("<input type=\"submit\" name=\"submit\" value=\"Submit\">");
            writer.println("</Form>");
            writer.println("</body>");
            writer.println("</html>");
        }
    }
}
