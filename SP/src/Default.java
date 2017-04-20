import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;

/**
 * Created by Nassim on 20/04/2017.
 */
@WebServlet(name = "Default")
public class Default extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String clientIp = request.getRemoteAddr();

        String[] selectedService = request.getParameterValues("serviceSelection");
        String[] selectedData = request.getParameterValues("eIDdataSelector");
        ArrayList<String> sd=new ArrayList<String>();

        for(String s :selectedData){  //stupid stuff to use a parser
            sd.add("\""+s+"\"");
        }

        System.out.println("Selected eID Data: "+ sd.toString());

        JSONObject jo = new JSONObject();
        JSONParser parser = new JSONParser();
        JSONArray eIDData= null;
        try {
            eIDData = (JSONArray)parser.parse(sd.toString());
        } catch (ParseException e) {
            e.printStackTrace();
        }

        jo.put("selectedData", eIDData);
        jo.put("domain","Default");
        jo.put("service",selectedService[0]);
        jo.put("cert","DefaultCert");

        System.out.println(jo.toJSONString());
        MiddlewareComm comm = new MiddlewareComm();
        comm.sendCert(clientIp,jo.toJSONString());

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
            writer.println("<br><br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"name\">Name<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"address\">Address<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"country\">Country<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"birth_date\">Birth Date<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"age\">Age<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"gender\">Gender<br>");
            writer.println("<input type=\"checkbox\" name=\"eIDdataSelector\" value=\"picture\">Picture<br>");
            writer.println("<input type=\"submit\" name=\"submit\" value=\"Submit\">");
            writer.println("</Form>");
            writer.println("</body>");
            writer.println("</html>");
        }
    }
}
