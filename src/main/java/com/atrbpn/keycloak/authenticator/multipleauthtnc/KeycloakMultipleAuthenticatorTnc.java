package com.atrbpn.keycloak.authenticator.multipleauthtnc;

import com.atrbpn.keycloak.authenticator.multipleauthtnc.helper.PostgresDBHelper;
import com.atrbpn.keycloak.authenticator.multipleauthtnc.tnc.TncRequest;
import com.atrbpn.keycloak.authenticator.multipleauthtnc.tnc.TncResponse;
import com.atrbpn.keycloak.authenticator.multipleauthtnc.tnc.TncRestClient;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.model.TotpLoginBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordUserCredentialModel;
import org.keycloak.models.utils.FormMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.ws.rs.core.HttpHeaders;

import java.io.IOException;
import java.net.URLDecoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Properties;
import java.util.Random;
import java.util.UUID;

/**
 * <pre>
 *  com.atrbpn.keycloak.authenticator.multipleauth.KeycloakMultipleAuthenticator
 * </pre>
 *
 * @author Muhammad Edwin < edwin at redhat dot com >
 * 12 Jun 2025 17:00
 */
public class KeycloakMultipleAuthenticatorTnc implements Authenticator {

    private static final Logger log = LoggerFactory.getLogger(KeycloakMultipleAuthenticatorTnc.class);

    private static final String OTP_EMAIL = "email";

    private static final String OTP_AUTHENTICATOR = "authenticator";

    private static final String TPL_AUTHENTICATOR = "login-otp.ftl";

    private static final String TPL_EMAIL = "otp_email.ftl";

    private static final String Q_INSERT_OTP = "insert into otp (id, user_id, created_date, otp) \n" +
            "values (?, ?, current_timestamp, ?)";

    private static String smtpHost;
    private static String smtpFrom;

    private static String environment;
    private static String otpMechanism;

    static {
        try {
            Context initCxt =  new InitialContext();

            smtpHost = (String) initCxt.lookup("java:/smtpHost");
            smtpFrom = (String) initCxt.lookup("java:/smtpFrom");
            environment = (String) initCxt.lookup("java:/environment");
            otpMechanism = (String) initCxt.lookup("java:/otpMechanism");

        } catch (Exception ex) {
            log.error("unable to get jndi connection for SMTP or Environment");
            log.error(ex.getMessage(), ex);
        }
    }

    /**
     * Authenticate the user.
     *
     * @param authenticationFlowContext
     */
    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {

        // not bringing username
        if(authenticationFlowContext.getHttpRequest().getFormParameters().get("username") == null
                || authenticationFlowContext.getHttpRequest().getFormParameters().get("username").isEmpty()) {

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Username atau Password Salah"));

            return;
        }

        // not bringing password
        if(authenticationFlowContext.getHttpRequest().getFormParameters().get("password") == null
                || authenticationFlowContext.getHttpRequest().getFormParameters().get("password").isEmpty()) {
            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Username atau Password Salah"));

            return;
        }

        // capture username
        String username = authenticationFlowContext.getHttpRequest().getFormParameters().getFirst("username").trim();

        try {
            username = URLDecoder.decode(username, "UTF-8");
        } catch (Exception ex) {
            log.error(ex.getMessage());
        }

        // search for corresponding user
        UserModel userModel = authenticationFlowContext.getSession()
                .userStorageManager().getUserByUsername(username, authenticationFlowContext.getRealm());

        // user not exists
        if(userModel == null) {
            log.info(" invalid userModel for username : {} ", username);

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Username atau Password Salah"));

            return;
        }

        log.info(" fetching password for username : {} ", username);

        String password = authenticationFlowContext.getHttpRequest().getFormParameters().getFirst("password").trim();
        try {
            password = URLDecoder.decode(password, "UTF-8");
        } catch (Exception ex) {
            log.error(ex.getMessage());
        }

        // password is incorrect
        PasswordUserCredentialModel credentialInput = UserCredentialModel.password(password);
        boolean valid = authenticationFlowContext.getSession().userCredentialManager().isValid(authenticationFlowContext.getRealm(),
                userModel,
                new PasswordUserCredentialModel[]{credentialInput} );
        if( !valid ) {
            log.info(" invalid password for username : {} ", username);

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Username atau Password Salah"));

            return;
        }

        log.info(" fetching userModel for username : {} ", username);

        // putting usermodel to session
        authenticationFlowContext.setUser(userModel);
        authenticationFlowContext.getAuthenticationSession().setAuthNote("username", username);

        // putting kantor to session
        String kantor = authenticationFlowContext.getHttpRequest().getFormParameters().getFirst("kantor").trim();
        authenticationFlowContext.getAuthenticationSession().setAuthNote("kantor", kantor);

        //  get otp type
        String otpType = authenticationFlowContext.getHttpRequest().getDecodedFormParameters().getFirst("otpType").trim();
        authenticationFlowContext.getAuthenticationSession().setAuthNote("otpType", otpType);

        if(OTP_AUTHENTICATOR.equalsIgnoreCase(otpType)) {
            // using authenticator
            log.info(" displaying OTP_AUTHENTICATOR page for username : {} ", username);

            // move it to OTP Form
            authenticationFlowContext.success();

        } else if(OTP_EMAIL.equalsIgnoreCase(otpType)) {
            // otp thru email
            log.info(" displaying OTP_EMAIL page for username : {} ", username);

            // generate otp here
            generateOTPOnEmail(authenticationFlowContext, userModel);

            // get tnc from external api here
            if (TncRestClient.tncApiBaseUrl != null && !TncRestClient.tncApiBaseUrl.trim().isEmpty()) {
                log.info("starting tnc request for username : {} ", username);
                TncRequest tncRequest = new TncRequest(userModel.getAttributes().get("orcluserid").get(0), "internal");
                TncResponse tncResponse;
                try {
                    tncResponse = TncRestClient.verifyUser(tncRequest);
                    log.info("tnc response: {}", new ObjectMapper().writeValueAsString(tncResponse));

                    if (tncResponse != null)
                    {
                        authenticationFlowContext.form().setAttribute("tncMessage", tncResponse.getMessage());
                        if (tncResponse.getData() != null) {
                            authenticationFlowContext.form().setAttribute("tncStatus", tncResponse.getData().getStatusTnc());
                            authenticationFlowContext.form().setAttribute("tncContent", tncResponse.getData().getKonten());
                            authenticationFlowContext.form().setAttribute("tncVersionUpdated", tncResponse.getData().getVersiTncTerbaru());
                            authenticationFlowContext.form().setAttribute("tncUrl", tncResponse.getData().getUrl());

                            // set statusTnc to auth note for next process
                            String tncStatus = String.valueOf(tncResponse.getData().getStatusTnc());
                            authenticationFlowContext.getAuthenticationSession().setAuthNote("tncStatus", tncStatus);
                        } else {
                            log.warn("tnc response data is null");
                        }
                    } else {
                        log.warn("tnc response is null");
                    }
                } catch (IOException ex) {
                    log.error("error request tnc from external api");
                    log.error(ex.getMessage(), ex);
                }
            }

            authenticationFlowContext.forceChallenge(
                    authenticationFlowContext.form().setAttribute("realm", authenticationFlowContext.getRealm())
                            .createForm(TPL_EMAIL)
            );
        } else {
            // we should never reach this
            log.info(" invalid otpType for username : {} ", username);

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Username atau Password Salah"));

            return;
        }
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        authenticationFlowContext.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }

    private void generateOTPOnEmail(AuthenticationFlowContext authenticationFlowContext, UserModel userModel) {
        // give a random otp
        String randomOTP = String.format("%06d", new Random().nextInt(999999));

        // generate a default otp when env is development
        if("development".equalsIgnoreCase(environment)) {
            randomOTP = "111111";
        }

        // capture the ip from X-Forwarded-For header
        String ip = authenticationFlowContext.getHttpRequest().getHttpHeaders().getHeaderString("X-Forwarded-For");
        if(ip ==null)
            ip = authenticationFlowContext.getSession().getContext().getConnection().getRemoteAddr();
        String agent = authenticationFlowContext.getHttpRequest().getHttpHeaders().getHeaderString(HttpHeaders.USER_AGENT);

        // save otp into db
        saveOtp(userModel.getUsername(), randomOTP);

        if("email".equalsIgnoreCase(otpMechanism)) {
            final String myRandomOTP = randomOTP;
            final String myip = ip;

            // send async email
            Thread thread = new Thread() {
                public void run() {
                    try {
                        sendEmail(userModel, myRandomOTP, myip, agent);
                    } catch (Exception ex) {
                        log.error(ex.getMessage(), ex);
                    }
                }
            };
            thread.start();
        }
    }

    private void saveOtp(String userid, String otp) {

        log.info("Inserting OTP to PGSQL for user {}", userid);

        PreparedStatement st = null;
        Connection c = null;

        try {
            c = PostgresDBHelper.getConnection();

            st = c.prepareStatement(Q_INSERT_OTP);
            st.setString(1, UUID.randomUUID().toString());
            st.setString(2, userid);
            st.setString(3, otp);
            st.executeUpdate();
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        } finally {
            PostgresDBHelper.closeQuietly(c);
            PostgresDBHelper.closeQuietly(st);
        }
    }

    private void sendEmail(UserModel userModel, String randomOTP, String ip, String agent) throws Exception {
        log.info("begin sending email to {} - username {}", userModel.getEmail(), userModel.getUsername());

        Properties props = System.getProperties();

        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.ssl.trust", smtpHost);
        props.put("mail.smtp.host", smtpHost);
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.auth", "false");

        Session session = Session.getInstance(props);
        MimeMessage message = new MimeMessage(session);

        message.setFrom(new InternetAddress(smtpFrom));
        message.addRecipient(Message.RecipientType.TO, new InternetAddress(userModel.getEmail()));

        String emailBody = getEmailBody().toString().replace("OTP", randomOTP)
                .replace("USERNAME", userModel.getFirstName()+" "+userModel.getLastName())
                .replace("IP-ADDRESS", ip)
                .replace("USER-DEVICE", agent);
        message.setSubject("[ATR BPN] OTP Aplikasi");
        message.setContent(emailBody,
                "text/html; charset=utf-8");
        Transport transport = session.getTransport("smtp");
        transport.connect();
        transport.sendMessage(message, message.getAllRecipients());
        transport.close();

        log.info("successfully sending email to {} - username {}", userModel.getEmail(), userModel.getUsername());
    }

    private String getEmailBody() {
        return "<html>\n" +
                "<head></head>\n" +
                "<body>\n" +
                "<img src=\"https://login.atrbpn.go.id/images/atrbpn-icon.png\" />\n" +
                "<h2>Otorisasi Akun Aplikasi</h2>\n" +
                "\n" +
                "<p>USERNAME Pengguna Aplikasi Komputerisasi Kegiatan Pertanahan yang terhormat,</p>\n" +
                "<p>Anda baru saja mencoba untuk masuk ke akun Aplikasi anda. Sebagai pengukur keamanan, kami " +
                "membutuhkan konfirmasi\n" +
                "    tambahan sebelum mengizinkan mengakses akun Aplikasi anda.</p>\n" +
                "\n" +
                "IP Address: IP-ADDRESS <br/>\n" +
                "Device: USER-DEVICE <br/><br/>\n" +
                "JIka ini adalah aktivitas yang benar, Ini adalah kode aktivasi akun anda: <br/>\n" +
                "<b>OTP</b> <br/>\n" +
                "Jika aktivitas ini bukan dilakukan oleh anda sendiri, mohon rubah kata sandi segera.<br/>\n" +
                "<br/>\n" +
                "Demikian, Terimakasih.<br/>\n" +
                "<br/>\n" +
                "ATR/BPN Melayani, Profesional dan Terpercaya\n" +
                "</body>\n" +
                "</html>";
    }
}
