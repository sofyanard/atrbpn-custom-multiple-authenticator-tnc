package com.atrbpn.keycloak.authenticator.multipleauthtnc.tnc;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

import javax.naming.InitialContext;
import javax.naming.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TncRestClient {

    private static final Logger log = LoggerFactory.getLogger(TncRestClient.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    public static String tncApiBaseUrl;

    static {
        try {
            Context initCxt =  new InitialContext();

            tncApiBaseUrl = (String) initCxt.lookup("java:/tncApiBaseUrl");
            log.info("tncApiBaseUrl: {}", tncApiBaseUrl);

        } catch (Exception ex) {
            tncApiBaseUrl = null;
            log.error("unable to get jndi connection for SMTP or Environment");
            log.error(ex.getMessage(), ex);
        }
    }

    public static TncResponse verifyUser(TncRequest request) throws IOException {
        
        // Do REST POST request
        URL url = new URL(tncApiBaseUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        // Serialize TncRequest to JSON and send
        String jsonRequest = objectMapper.writeValueAsString(request);
        conn.getOutputStream().write(jsonRequest.getBytes("UTF-8"));

        int status = conn.getResponseCode();
        if (status != 200) {
            throw new IOException("REST request failed with status: " + status);
        }

        StringBuilder jsonBuilder = new StringBuilder();
        try (Scanner scanner = new Scanner(conn.getInputStream())) {
            while (scanner.hasNextLine()) {
                jsonBuilder.append(scanner.nextLine());
            }
        }
        conn.disconnect();
        String jsonString = jsonBuilder.toString();

        return objectMapper.readValue(jsonString, TncResponse.class);
    }

}
