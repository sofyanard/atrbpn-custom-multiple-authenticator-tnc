package com.atrbpn.keycloak.authenticator.multipleauthtnc.tnc;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TncResponse {

    @JsonProperty("success")
    private boolean success;

    @JsonProperty("message")
    private String message;

    @JsonProperty("data")
    private TncResponseData tncResponseData;

    // Getters and Setters

    public static class TncResponseData {

        @JsonProperty("USERID")
        private String userId;

        @JsonProperty("USERNAME")
        private String username;

        @JsonProperty("REALM")
        private String realm;

        @JsonProperty("TNC")
        private String tnc;

        @JsonProperty("VERSI_TNC_USER")
        private String versiTncUser;

        @JsonProperty("TNC_TERBARU_ID")
        private String tncTerbaruId;

        @JsonProperty("VERSI_TNC_TERBARU")
        private String versiTncTerbaru;

        @JsonProperty("TANGGALTNC")
        private String tanggaltnc;

        @JsonProperty("KONTEN")
        private String konten;

        @JsonProperty("URL")
        private String url;

        @JsonProperty("STATUS_TNC")
        private int statusTnc;

        // Getters and Setters
        public String getUserId() { return userId; }
        public String getUsername() { return username; }
        public String getRealm() { return realm; }
        public String getTnc() { return tnc; }
        public String getVersiTncUser() { return versiTncUser; }
        public String getTncTerbaruId() { return tncTerbaruId; }
        public String getVersiTncTerbaru() { return versiTncTerbaru; }
        public String getTanggaltnc() { return tanggaltnc; }
        public String getKonten() { return konten; }
        public String getUrl() { return url; }
        public int getStatusTnc() { return statusTnc; }
    }

    public boolean isSuccess() { return success; }
    public String getMessage() { return message; }
    public TncResponseData getData() { return tncResponseData; }

}
