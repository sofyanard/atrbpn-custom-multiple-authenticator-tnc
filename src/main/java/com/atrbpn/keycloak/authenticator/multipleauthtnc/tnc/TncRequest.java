package com.atrbpn.keycloak.authenticator.multipleauthtnc.tnc;

public class TncRequest {

    private String userid;
    private String realm;

    public TncRequest() {}

    public TncRequest(String userid, String realm) {
        this.userid = userid;
        this.realm = realm;
    }

    public String getUserid() {
        return userid;
    }

    public void setUserid(String userid) {
        this.userid = userid;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

}
