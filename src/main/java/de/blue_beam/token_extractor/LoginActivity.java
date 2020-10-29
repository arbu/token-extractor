/*
 * Copyright (C) 2013-2017 microG Project Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.blue_beam.token_extractor;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.sun.javafx.webkit.WebConsoleListener;
import javafx.application.Application;
import javafx.concurrent.Worker.State;
import javafx.scene.Scene;
import javafx.scene.layout.VBox;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javafx.stage.Stage;
import netscape.javascript.JSObject;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;


public class LoginActivity extends Application {
    private static final Logger LOGGER = Logger.getLogger(LoginActivity.class.getName());

    private static final String EMBEDDED_SETUP_URL = "https://accounts.google.com/EmbeddedSetup";
    private static final String PROGRAMMATIC_AUTH_URL = "https://accounts.google.com/o/oauth2/programmatic_auth";
    private static final String GOOGLE_SUITE_URL = "https://accounts.google.com/signin/continue";
    private static final String TOKEN_AUTH_URL = "https://android.clients.google.com/auth";
    private static final String COOKIE_OAUTH_TOKEN = "oauth_token";
    private static final int BUILD_VERSION_SDK = 28;
    private static final int PLAY_SERVICES_VERSION_CODE = 19629032;
    private static final String WEBKIT_USER_AGENT = "Mozilla/5.0 (Linux; Android 9; VirtualBox Build/PI; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/78.0.3904.96 Safari/537.36 MinuteMaid";
    private static final String AUTH_USER_AGENT = "GoogleAuth/1.4 (x86_64 PI); gzip";

    private WebEngine webEngine;
    private JsBridge jsBridge;
    private CookieManager cookieManager;
    private Stage stage;
    private HttpClient httpClient;
    private String accountId = "";

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws NoSuchAlgorithmException {
        // allow redirect headers
        System.setProperty("sun.net.http.allowRestrictedHeaders", "true");

        httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .sslContext(SSLContext.getDefault())
                .sslParameters(new SSLParameters())
                .build();

        WebView webView = new WebView();

        cookieManager = new CookieManager();
        CookieManager.setDefault(cookieManager);

        webEngine = webView.getEngine();

        webEngine.setUserAgent(WEBKIT_USER_AGENT);

        jsBridge = new JsBridge();
        webEngine.getLoadWorker().stateProperty().addListener((ov, oldState, newState) -> {
            if (newState == State.SUCCEEDED) {
                JSObject jsObject = (JSObject) webEngine.executeScript("window");
                jsObject.setMember("mm", jsBridge);
            }

        });

        webEngine.locationProperty().addListener((observable, oldLocation, newLocation) -> {
            LOGGER.finest("new location: " + newLocation);

            String fragment = null;
            try {
                fragment = new URI(newLocation).getFragment();
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }

            // Normal login.
            if ("close".equals(fragment)) {
                closeWeb(false);
            }

            // Google Suite login.
            else if (newLocation.startsWith(GOOGLE_SUITE_URL)) {
                closeWeb(false);
            }

            // IDK when this is called.
            else if (newLocation.startsWith(PROGRAMMATIC_AUTH_URL)) {
                closeWeb(true);
            }
        });

        // TODO: this functionality is not exported by default and the according
        //       flags can not be set in gradle
        //WebConsoleListener.setDefaultListener((webViewInstance, message, lineNumber, sourceId) ->
        //        LOGGER.fine("Console: [" + sourceId + ":" + lineNumber + "] " + message));

        Map<String, String> params = new HashMap<>();
        params.put("source", "android");
        params.put("xoauth_display_name", "Android Device");
        params.put("lang", Locale.getDefault().getLanguage());
        params.put("cc", Locale.getDefault().getCountry().toLowerCase(Locale.US));
        params.put("langCountry", Locale.getDefault().toString().toLowerCase(Locale.US));
        params.put("hl", Locale.getDefault().toString().replace("_", "-"));
        params.put("tmpl", "new_account");

        webEngine.load(params.entrySet().stream()
                .map(entry -> {
                    try {
                        return entry.getKey() + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name());
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    return "";
                })
                .collect(Collectors.joining("&", EMBEDDED_SETUP_URL + "?", "")));

        VBox box = new VBox(webView);
        Scene scene = new Scene(box, 400, 540);
        stage = primaryStage;
        stage.setScene(scene);
        stage.setTitle("Google Login");
        stage.show();
    }

    private void closeWeb(boolean programmaticAuth) {
        try {
            URI uri = new URI(programmaticAuth ? PROGRAMMATIC_AUTH_URL : EMBEDDED_SETUP_URL);
            List<HttpCookie> cookies = cookieManager.getCookieStore().get(uri);
            for (HttpCookie cookie : cookies) {
                if(cookie.getName().equals(COOKIE_OAUTH_TOKEN)) {
                    LOGGER.fine("oauth token: " + cookie.getValue());
                    retrieveAc2dmToken(cookie.getValue());
                    break;
                }
            }
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        stage.close();
    }

    private void abortLogin() {
        LOGGER.severe("Login aborted");
        stage.close();
    }

    private void retrieveAc2dmToken(String oAuthToken) {
        Map<String, String> body = new TreeMap<>();
        body.put("lang", Locale.getDefault().toString().replace("_", "-"));
        body.put("google_play_services_version", String.valueOf(PLAY_SERVICES_VERSION_CODE));
        body.put("sdk_version", String.valueOf(BUILD_VERSION_SDK));
        body.put("device_country", Locale.getDefault().getCountry().toLowerCase(Locale.US));
        body.put("Email", this.accountId);
        body.put("service", "ac2dm");
        body.put("get_accountid", "1");
        body.put("ACCESS_TOKEN", "1");
        body.put("callerPkg", "com.google.android.gms");
        body.put("add_account", "1");
        body.put("Token", oAuthToken);
        //body.put("droidguard_results", "...");
        body.put("callerSig", "38918a453d07199354f8b19af05ec6562ced5788");

        String bodyString = body.entrySet().stream()
                .map(entry -> {
                    try {
                        return entry.getKey() + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name());
                    } catch (UnsupportedEncodingException e) {
                        e.printStackTrace();
                    }
                    return "";
                })
                .collect(Collectors.joining("&"));

        HttpRequest request = HttpRequest
                .newBuilder(URI.create(TOKEN_AUTH_URL))
                .POST(HttpRequest.BodyPublishers.ofString(bodyString))
                .setHeader("app", "com.google.android.gms")
                .setHeader("User-Agent", AUTH_USER_AGENT)
                .setHeader("content-type", "application/x-www-form-urlencoded")
                .build();

        HttpResponse<Stream<String>> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofLines());
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return;
        }

        if (response.statusCode() != 200 && response.statusCode() != 401 && response.statusCode() != 403) {
            LOGGER.severe("AC2DM Token: Unexpected response code: HTTP " + response.statusCode());
            return;
        }

        Map<String, String> data = response.body().collect(Collectors.toMap(line -> line.substring(0, line.indexOf("=")), line -> line.substring(line.indexOf("=") + 1)));

        if (response.statusCode() != 200 || data.containsKey("Error")) {
            String error = data.getOrDefault("Error", "Unknown Error (HTTP " + response.statusCode() + ")");
            LOGGER.severe("AC2DM Token: API returned an error: " + error);
            return;
        }

        if (!data.containsKey("Token")) {
            LOGGER.severe("AC2DM Token: Missing 'Token' in API response");
            return;
        }

        String tokenLine = accountId + " " + data.get("Token");
        System.out.println(tokenLine);
        try {
            Files.write(Paths.get("tokens.txt"), (tokenLine + "\n").getBytes(), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public class JsBridge {

        private void debug(String name, String... args) {
            LOGGER.finer("JavaScript call to " + name + "(" + String.join(", ", args) + ")");
        }

        @SuppressWarnings("unused")
        public void addAccount(String json) {
            debug("closeView", json);
        }

        @SuppressWarnings("unused")
        public void closeView() {
            debug("closeView");
            closeWeb(false);
        }

        @SuppressWarnings("unused")
        public String fetchVerifiedPhoneNumber() {
            debug("fetchVerifiedPhoneNumber");
            return null;
        }

        @SuppressWarnings("unused")
        public String getAccounts() {
            debug("getAccounts");
            return "[]";
        }

        @SuppressWarnings("unused")
        public String getAllowedDomains() {
            debug("getAllowedDomains");
            return "[]";
        }

        @SuppressWarnings("unused")
        public String getAndroidId() {
            debug("getAndroidId");
            return null;
        }

        @SuppressWarnings("unused")
        public int getAuthModuleVersionCode() {
            debug("getAuthModuleVersionCode");
            return 1;
        }

        @SuppressWarnings("unused")
        public int getBuildVersionSdk() {
            debug("getBuildVersionSdk");
            return BUILD_VERSION_SDK;
        }

        @SuppressWarnings("unused")
        public void getDroidGuardResult(String s) {
            debug("getDroidGuardResult", s);
        }

        @SuppressWarnings("unused")
        public int getDeviceDataVersionInfo() {
            debug("getDeviceDataVersionInfo");
            return 1;
        }

        @SuppressWarnings("unused")
        public String getFactoryResetChallenges() {
            debug("getFactoryResetChallenges");
            return "[]";
        }

        @SuppressWarnings("unused")
        public String getPhoneNumber() {
            debug("getPhoneNumber");
            return null;
        }

        @SuppressWarnings("unused")
        public int getPlayServicesVersionCode() {
            debug("getPlayServicesVersionCode");
            return PLAY_SERVICES_VERSION_CODE;
        }

        @SuppressWarnings("unused")
        public String getSimSerial() {
            debug("getSimSerial");
            return null;
        }

        @SuppressWarnings("unused")
        public int getSimState() {
            debug("getSimState");
            return 0; //SIM_STATE_UNKNOWN;
        }

        @SuppressWarnings("unused")
        public void goBack() {
            debug("goBack");
        }

        @SuppressWarnings("unused")
        public boolean hasPhoneNumber() {
            debug("hasPhoneNumber");
            return false;
        }

        @SuppressWarnings("unused")
        public boolean hasTelephony() {
            debug("hasTelephony");
            return false;
        }

        @SuppressWarnings("unused")
        public void hideKeyboard() {
            debug("hideKeyboard");
        }

        @SuppressWarnings("unused")
        public boolean isUserOwner() {
            debug("isUserOwner");
            return true;
        }

        @SuppressWarnings("unused")
        public void launchEmergencyDialer() {
            debug("launchEmergencyDialer");
        }

        @SuppressWarnings("unused")
        public void log(String s) {
            debug("log", s);
        }

        @SuppressWarnings("unused")
        public void notifyOnTermsOfServiceAccepted() {
            debug("notifyOnTermsOfServiceAccepted");
        }

        @SuppressWarnings("unused")
        public void setAccountIdentifier(String accountIdentifier) {
            debug("setAccountIdentifier " + accountIdentifier);
            if(accountIdentifier != null)
                accountId = accountIdentifier;
        }

        @SuppressWarnings("unused")
        public void setBackButtonEnabled(boolean backButtonEnabled) {
            debug("setBackButtonEnabled", String.valueOf(backButtonEnabled));
        }

        @SuppressWarnings("unused")
        public void setNewAccountCreated() {
            debug("setNewAccountCreated");
        }

        @SuppressWarnings("unused")
        public void showKeyboard() {
            debug("showKeyboard");
        }

        @SuppressWarnings("unused")
        public void showView() {
            debug("showView");
        }

        @SuppressWarnings("unused")
        public void skipLogin() {
            debug("skipLogin");
            abortLogin();
        }

        @SuppressWarnings("unused")
        public void startAfw() {
            debug("startAfw");
        }

    }
}
