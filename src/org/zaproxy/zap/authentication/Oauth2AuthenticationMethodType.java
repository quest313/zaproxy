package org.zaproxy.zap.authentication;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.db.RecordContext;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.api.ApiDynamicActionImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.DefaultNameValuePair;
import org.zaproxy.zap.model.NameValuePair;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.session.WebSession;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ZapTextField;
import org.zaproxy.zap.view.LayoutHelper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.function.UnaryOperator;

public class OAuth2AuthenticationMethodType extends PostBasedAuthenticationMethodType {

    private static final String METHOD_NAME = Constant.messages.getString("authentication.method.oauth2.name");

    private static final int METHOD_IDENTIFIER = 6;

    private static final String API_METHOD_NAME = "formBasedAuthentication";

    private static final Logger LOGGER = Logger.getLogger(OAuth2AuthenticationMethodType.class);
    private HttpSender httpSender;

    private static final UnaryOperator<String> PARAM_ENCODER = value -> {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ignore) {
            // Standard charset.
        }
        return "";
    };

    private static final UnaryOperator<String> PARAM_DECODER = value -> {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException ignore) {
            // Standard charset.
        } catch (IllegalArgumentException e) {
            LOGGER.debug("Failed to URL decode: " + value, e);
        }
        return "";
    };




    public OAuth2AuthenticationMethodType() {
        super(METHOD_NAME, METHOD_IDENTIFIER, API_METHOD_NAME, "authentication.method.jb.popup.login.request", true);
    }


    private static final String AUTHENTICATION_URL_LABEL = Constant.messages
            .getString("authentication.method.oauth2.field.label.auth.url");

    private static final String ACCESS_TOKEN_URL_LABEL = Constant.messages
            .getString("authentication.method.oauth2.field.label.access.token.url");

    private static final String CLIENT_ID_LABEL = Constant.messages
            .getString("authentication.method.oauth2.field.label.client.id");

    private static final String CLIENT_SECRET_LABEL = Constant.messages
            .getString("authentication.method.oauth2.field.label.client.secret");

    private static final String CALLBACK_URL_LABEL = Constant.messages
            .getString("authentication.method.oauth2.field.label.callback.url");

    private static final String POST_DATA_LABEL = Constant.messages
            .getString("authentication.method.pb.field.label.postData");

    private static final String POST_DATA_REQUIRED_LABEL = Constant.messages
            .getString("authentication.method.pb.field.label.postDataRequired");

    private static final String USERNAME_PARAM_LABEL = Constant.messages
            .getString("authentication.method.pb.field.label.usernameParam");

    private static final String PASSWORD_PARAM_LABEL = Constant.messages
            .getString("authentication.method.pb.field.label.passwordParam");

    private static final String AUTH_DESCRIPTION = Constant.messages
            .getString("authentication.method.pb.field.label.description");


    @Override
    public Oauth2AuthenticationMethod createAuthenticationMethod(int contextId) {
        return new Oauth2AuthenticationMethod();
    }

    @Override
    public String getName() {
        return METHOD_NAME;
    }

    @Override
    public int getUniqueIdentifier() {
        return METHOD_IDENTIFIER;
    }

    @Override
    public AbstractAuthenticationMethodOptionsPanel buildOptionsPanel(Context uiSharedContext) {
        return new Oauth2AuthenticationMethodOptionsPanel(uiSharedContext, PARAM_DECODER);
    }

    @Override
    public boolean hasOptionsPanel() {
        return true;
    }

    @Override
    public AbstractCredentialsOptionsPanel<? extends AuthenticationCredentials> buildCredentialsOptionsPanel(AuthenticationCredentials credentials, Context uiSharedContext) {
        return null;
    }

    @Override
    public boolean hasCredentialsOptionsPanel() {
        return false;
    }

    @Override
    public boolean isTypeForMethod(AuthenticationMethod method) {
        return false;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {

    }




    @Override
    public void exportData(Configuration config, AuthenticationMethod authMethod) {

    }

    @Override
    public void importData(Configuration config, AuthenticationMethod authMethod) throws ConfigurationException {

    }


    @Override
    public ApiDynamicActionImplementor getSetMethodForContextApiAction() {
        return null;
    }

    @Override
    public ApiDynamicActionImplementor getSetCredentialsForUserApiAction() {
        return null;
    }

    protected HttpSender getHttpSender() {
        if (this.httpSender == null) {
            this.httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(),
                    true, HttpSender.AUTHENTICATION_INITIATOR);
        }
        return httpSender;
    }

    // move later to method
    protected static void authenticate(String authenticationUrl) throws Exception {
        HttpMessage authRequest = new HttpMessage(new URI(authenticationUrl, true));

        // move this to method like in pbamt
        HttpSender httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(),
                true, HttpSender.AUTHENTICATION_INITIATOR);


        httpSender.sendAndReceive(authRequest);
        AuthenticationHelper.addAuthMessageToHistory(authRequest);

    }

    public class Oauth2AuthenticationMethod extends PostBasedAuthenticationMethod {

        public Oauth2AuthenticationMethod() {
            this(null);
        }


        private String authenticationUrl = "";
        private String accessTokenUrl = "";
        private String callbackUrl = "";
        private String clientId = "";
        private String clientSecret = "";



        private String postData = "";

        public Oauth2AuthenticationMethod(Oauth2AuthenticationMethod oauth2AuthenticationMethod) {

            super(HttpHeader.FORM_URLENCODED_CONTENT_TYPE, PARAM_ENCODER, oauth2AuthenticationMethod);

            if(oauth2AuthenticationMethod != null) {
                this.setAuthenticationUrl(oauth2AuthenticationMethod.getAuthenticationUrl());
                this.setAccessTokenUrl(oauth2AuthenticationMethod.getAccessTokenUrl());
                this.setCallbackUrl(oauth2AuthenticationMethod.getCallbackUrl());
                this.setClientId(oauth2AuthenticationMethod.getClientId());
                this.setClientSecret(oauth2AuthenticationMethod.getClientSecret());
            }
        }

        @Override
        public boolean isConfigured() {
            return false;
        }

        @Override
        protected AuthenticationMethod duplicate() {
            return new Oauth2AuthenticationMethod(this);
        }

        @Override
        public AuthenticationCredentials createAuthenticationCredentials() {
            return null;
        }

        @Override
        public AuthenticationMethodType getType() {
            return new OAuth2AuthenticationMethodType();
        }

        @Override
        public WebSession authenticate(SessionManagementMethod sessionManagementMethod,
                                       AuthenticationCredentials credentials,
                                       User user) throws UnsupportedAuthenticationCredentialsException {
            return null;

        }



        @Override
        public ApiResponse getApiResponseRepresentation() {
            return null;
        }

        public String getAccessTokenUrl() {
            return accessTokenUrl;
        }

        public void setAccessTokenUrl(String accessTokenUrl) {
            this.accessTokenUrl = accessTokenUrl;
        }

        public String getAuthenticationUrl() {
            return authenticationUrl;
        }

        public void setAuthenticationUrl(String authenticaitionUrl) {
            this.authenticationUrl = authenticaitionUrl;
        }

        public String getCallbackUrl() {
            return callbackUrl;
        }

        public void setCallbackUrl(String callbackUrl) {
            this.callbackUrl = callbackUrl;
        }

        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getPostData() { return postData; }

        public void setPostData(String postData) { this.postData = postData; }
    }
    protected class Oauth2AuthenticationMethodOptionsPanel extends
            AbstractAuthenticationMethodOptionsPanel {

        private ZapTextField authenticationUrlField;
        private ZapTextField accessTokenUrlField;
        private ZapTextField callbackUrlField;
        private ZapTextField clientIdField;
        private ZapTextField clientSecretField;
        private ZapTextField postDataField;

        private JComboBox<NameValuePair> usernameParameterCombo;
        private JComboBox<NameValuePair> passwordParameterCombo;


        private Context context;
        private ExtensionUserManagement userExt = null;
        private Oauth2AuthenticationMethod authenticationMethod;

        private UnaryOperator<String> paramDecoder;


        public Oauth2AuthenticationMethodOptionsPanel(Context context, UnaryOperator<String> paramDecoder) {
            initialize();
            this.paramDecoder = paramDecoder;
            this.context = context;
        }

        private void initialize() {
            this.setLayout(new GridBagLayout());

            this.authenticationUrlField = new ZapTextField();
            this.accessTokenUrlField = new ZapTextField();
            this.callbackUrlField = new ZapTextField();
            this.clientIdField = new ZapTextField();
            this.clientSecretField = new ZapTextField();
            this.postDataField = new ZapTextField();

            this.add(new JLabel(AUTHENTICATION_URL_LABEL), LayoutHelper.getGBC(0, 0, 0, 1.0d, 0.0d));
            this.add(authenticationUrlField, LayoutHelper.getGBC(0, 1, 0, 1.0d, 0.0d));

            this.add(new JLabel(ACCESS_TOKEN_URL_LABEL), LayoutHelper.getGBC(0,2,0, 1.0d, 0.0d));
            this.add(accessTokenUrlField, LayoutHelper.getGBC(0,3,0,1.0d, 0.0d));

            this.add(new JLabel(CALLBACK_URL_LABEL), LayoutHelper.getGBC(0,4,0, 1.0d, 0.0d));
            this.add(callbackUrlField, LayoutHelper.getGBC(0,5,0, 1.0d, 0.0d));

            this.add(new JLabel((CLIENT_ID_LABEL)), LayoutHelper.getGBC(0,6,0, 1.0d, 0.0d));
            this.add(clientIdField, LayoutHelper.getGBC(0,7,0, 1.0d, 0.0d));

            this.add(new JLabel((CLIENT_SECRET_LABEL)), LayoutHelper.getGBC(0,8,0, 1.0d, 0.0d));
            this.add(clientSecretField, LayoutHelper.getGBC(0,9,0, 1.0d, 0.0d));

            this.add(new JLabel(POST_DATA_LABEL), LayoutHelper.getGBC(0, 10, 0, 1.0d, 0.0d));
            this.add(this.postDataField, LayoutHelper.getGBC(0, 11, 0, 1.0d, 0.0d));

            this.add(new JLabel(USERNAME_PARAM_LABEL), LayoutHelper.getGBC(0, 12, 0, 1.0d, 0.0d));
            this.usernameParameterCombo = new JComboBox<>();
            this.usernameParameterCombo.setRenderer(NameValuePairRenderer.INSTANCE);
            this.add(usernameParameterCombo, LayoutHelper.getGBC(0, 13, 0, 1.0d, 0.0d));

            this.add(new JLabel(PASSWORD_PARAM_LABEL), LayoutHelper.getGBC(1, 14, 0, 1.0d, 0.0d));
            this.passwordParameterCombo = new JComboBox<>();
            this.passwordParameterCombo.setRenderer(NameValuePairRenderer.INSTANCE);
            this.add(passwordParameterCombo, LayoutHelper.getGBC(1, 15, 0, 1.0d, 0.0d));

            this.add(new JLabel(AUTH_DESCRIPTION), LayoutHelper.getGBC(0, 16, 0, 1.0d, 0.0d));

            // Make sure we update the parameters when something has been changed in the
            // postDataField
            this.postDataField.addFocusListener(new FocusAdapter() {
                @Override
                public void focusLost(FocusEvent e) {
                    updateParameters();
                }
            });

        }

        /**
         * Gets the index of the parameter with a given value.
         *
         * @param params the params
         * @param value the value
         * @return the index of param with value, or -1 if no match was found
         */
        private int getIndexOfParamWithValue(NameValuePair[] params, String value) {
            for (int i = 0; i < params.length; i++)
                if (value.equals(params[i].getValue()))
                    return i;
            return -1;
        }

        private void updateParameters() {
            try {
                java.util.List<NameValuePair> params = extractParameters(this.postDataField.getText());
                NameValuePair[] paramsArray = params.toArray(new NameValuePair[params.size()]);
                this.usernameParameterCombo.setModel(new DefaultComboBoxModel<>(paramsArray));
                this.passwordParameterCombo.setModel(new DefaultComboBoxModel<>(paramsArray));

                int index = getIndexOfParamWithValue(paramsArray,
                        PostBasedAuthenticationMethod.MSG_USER_PATTERN);
                if (index >= 0) {
                    this.usernameParameterCombo.setSelectedIndex(index);
                }

                index = getIndexOfParamWithValue(paramsArray, PostBasedAuthenticationMethod.MSG_PASS_PATTERN);
                if (index >= 0) {
                    this.passwordParameterCombo.setSelectedIndex(index);
                }
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }

        protected List<NameValuePair> extractParameters(String postData) {
            List<NameValuePair> parameters = new ArrayList<>();
            getContext().getPostParamParser().parse(postData).forEach((k, v) -> parameters.add(new DefaultNameValuePair(k, v)));
            return parameters;
        }

        /**
         * Gets the context being configured.
         *
         * @return the context, never {@code null}.
         */
        protected Context getContext() {
            return context;
        }


        @Override
        public void validateFields() throws IllegalStateException {

        }

        @Override
        public void saveMethod() {
            Oauth2AuthenticationMethod method = (Oauth2AuthenticationMethod) this.getMethod();
            method.setAuthenticationUrl(authenticationUrlField.getText());
            method.setAccessTokenUrl(accessTokenUrlField.getText());
            method.setCallbackUrl(callbackUrlField.getText());
            method.setClientId(clientIdField.getText());
            method.setClientSecret(clientSecretField.getText());

            String postData = postDataField.getText();

            // TODO: 4/26/19 Remove duplication with PBAMT
            //noinspection Duplicates
            if (!postData.isEmpty()) {
                NameValuePair userParam = (NameValuePair) usernameParameterCombo.getSelectedItem();
                NameValuePair passwdParam = (NameValuePair) passwordParameterCombo.getSelectedItem();

                ExtensionUserManagement userExt = getUserExt();
                if (userExt != null && userExt.getUIConfiguredUsers(context.getIndex()).size() == 0) {
                    String username = userParam.getValue();
                    String password = passwdParam.getValue();
                    if (!username.isEmpty() && !username.contains(PostBasedAuthenticationMethod.MSG_USER_PATTERN)
                            && !password.contains(PostBasedAuthenticationMethod.MSG_PASS_PATTERN)) {
                        // Add the user based on the details provided
                        String userStr = paramDecoder.apply(username);
                        String passwdStr = paramDecoder.apply(password);
                        if (!userStr.isEmpty() && !passwdStr.isEmpty()) {
                            User user = new User(context.getIndex(), userStr);
                            UsernamePasswordAuthenticationCredentials upac =
                                    new UsernamePasswordAuthenticationCredentials(userStr, passwdStr);
                            user.setAuthenticationCredentials(upac);
                            getUserExt().getContextUserAuthManager(context.getIndex()).addUser(user);
                        }
                    }
                }

                postData = this.replaceParameterValue(postData, userParam,
                        PostBasedAuthenticationMethod.MSG_USER_PATTERN);
                postData = this.replaceParameterValue(postData, passwdParam,
                        PostBasedAuthenticationMethod.MSG_PASS_PATTERN);

            }
        }

        // TODO: 4/26/19 Remove duplication with PBAMT
        private ExtensionUserManagement getUserExt() {
            if (userExt == null) {
                userExt = Control.getSingleton().getExtensionLoader().getExtension(ExtensionUserManagement.class);

            }
            return userExt;
        }

        // TODO: 4/26/19 Remove duplication with PBAMT
        protected String replaceParameterValue(String originalString, NameValuePair parameter, String replaceString) {
            String keyValueSeparator = getContext().getPostParamParser().getDefaultKeyValueSeparator();
            String nameAndSeparator = parameter.getName() + keyValueSeparator;
            // Make sure we handle the case when there's only the parameter name in the POST data instead of
            // parameter name + separator + value (e.g. just 'param1&...' instead of 'param1=...&...')
            if (originalString.contains(nameAndSeparator)) {
                return originalString.replace(nameAndSeparator + parameter.getValue(), nameAndSeparator + replaceString);
            }
            return originalString.replace(parameter.getName(), nameAndSeparator + replaceString);
        }

        @Override
        public void bindMethod(AuthenticationMethod method) throws UnsupportedAuthenticationMethodException {
            this.authenticationMethod = (Oauth2AuthenticationMethod) method;
            this.authenticationUrlField.setText(authenticationMethod.authenticationUrl);
            this.accessTokenUrlField.setText(authenticationMethod.accessTokenUrl);
            this.callbackUrlField.setText(authenticationMethod.callbackUrl);
            this.clientIdField.setText(authenticationMethod.clientId);
            this.clientSecretField.setText(authenticationMethod.clientSecret);
            this.postDataField.setText(authenticationMethod.postData);

        }

        @Override
        public AuthenticationMethod getMethod() {
            return this.authenticationMethod;
        }
    }

    @Override
    public void persistMethodToSession(Session session, int contextId, AuthenticationMethod authMethod)
            throws DatabaseException {
        if (!(authMethod instanceof OAuth2AuthenticationMethodType.Oauth2AuthenticationMethod)) {
            throw new UnsupportedAuthenticationMethodException(
                    "OAuth2 type only supports: " + OAuth2AuthenticationMethodType.Oauth2AuthenticationMethod.class);
        }

        OAuth2AuthenticationMethodType.Oauth2AuthenticationMethod  method
                = (OAuth2AuthenticationMethodType.Oauth2AuthenticationMethod) authMethod;

        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1, method.getAuthenticationUrl());
        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_2, method.getAccessTokenUrl());
        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_3, method.getCallbackUrl());
        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_4, method.getClientId());
        session.setContextData(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_5, method.getClientSecret());
    }

    @Override
    public AuthenticationMethod loadMethodFromSession(Session session, int contextId) throws DatabaseException {
        OAuth2AuthenticationMethodType.Oauth2AuthenticationMethod method = createAuthenticationMethod(contextId);


        // Nuts
        java.util.List<String> authUrls = session.getContextDataStrings(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_1);
        String authenticationUrl = "";
        if (authUrls != null && authUrls.size() > 0) {
            authenticationUrl = authUrls.get(0);
        }

        java.util.List<String> accessTokenUrls = session.getContextDataStrings(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_2);
        String accessTokenUrl = "";
        if (accessTokenUrls != null && accessTokenUrls.size() > 0) {
            accessTokenUrl = accessTokenUrls.get(0);
        }

        java.util.List<String> callBackUrls = session.getContextDataStrings(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_3);
        String callBackUrl = "";
        if (callBackUrls != null && callBackUrls.size() > 0) {
            callBackUrl = callBackUrls.get(0);
        }

        java.util.List<String> clientIds = session.getContextDataStrings(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_4);
        String clientId = "";
        if (clientIds != null && clientIds.size() > 0) {
            clientId = clientIds.get(0);
        }

        java.util.List<String> clientSecrets = session.getContextDataStrings(contextId, RecordContext.TYPE_AUTH_METHOD_FIELD_5);
        String clientSecret = "";
        if (clientSecrets != null && clientSecrets.size() > 0) {
            clientSecret = clientSecrets.get(0);
        }

        try {
            method.setAuthenticationUrl(authenticationUrl);
            method.setAccessTokenUrl(accessTokenUrl);
            method.setCallbackUrl(callBackUrl);
            method.setClientId(clientId);
            method.setClientSecret(clientSecret);
        } catch (Exception e) {
            LOGGER.error("Unable to load OAuth2 authentication method data:", e);
        }
        return method;
    }
}
