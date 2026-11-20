import java.sql.*;
import java.util.*;

public class App {
    private static final String API_KEY = "AKIAABCDEFGHIJKLMNOP";
    private static final String DB_PASSWORD = "java_secret_2024";

    public void login(String user, String pass) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE name='" + user + "' AND pass='" + pass + "'";
        stmt.executeQuery(query);
    }

    public void runCommand(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }
}
