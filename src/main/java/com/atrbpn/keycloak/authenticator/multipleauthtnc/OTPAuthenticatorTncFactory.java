package com.atrbpn.keycloak.authenticator.multipleauthtnc;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * <pre>
 *  com.atrbpn.keycloak.authenticator.multipleauth.OTPAuthenticatorFactory
 * </pre>
 *
 * @author Muhammad Edwin < edwin at redhat dot com >
 * 14 Jun 2025 15:10
 */
public class OTPAuthenticatorTncFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {

    public static final String PROVIDER_ID = "atr-bpn-otp-authenticator-tnc";

    private static final OTPAuthenticatorTnc SINGLETON = new OTPAuthenticatorTnc();

    public String getDisplayType() {
        return "ATR BPN OTP Authenticator TnC";
    }

    public String getReferenceCategory() {
        return "ATR BPN OTP Authenticator TnC";
    }

    public boolean isConfigurable() {
        return false;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    public boolean isUserSetupAllowed() {
        return false;
    }

    public String getHelpText() {
        return "ATR BPN OTP Authenticator TnC";
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    public List<ProviderConfigProperty> getConfigProperties() {
        return new ArrayList<ProviderConfigProperty>();
    }

    public Authenticator create(KeycloakSession keycloakSession) {
        return SINGLETON;
    }

    public void init(Config.Scope scope) {

    }

    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    public void close() {

    }

    public String getId() {
        return PROVIDER_ID;
    }

    public int order() {
        return 0;
    }

}
