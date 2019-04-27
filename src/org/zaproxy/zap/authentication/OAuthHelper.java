package org.zaproxy.zap.authentication;

import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;

public class OAuthHelper {

    // move later to method
    protected static void authenticate(String authenticationUrl) throws Exception {
        HttpMessage authRequest = new HttpMessage(new URI(authenticationUrl, true));

        // move this to method like in pbamt
        HttpSender httpSender = new HttpSender(Model.getSingleton().getOptionsParam().getConnectionParam(),
                true, HttpSender.AUTHENTICATION_INITIATOR);


        httpSender.sendAndReceive(authRequest);
        AuthenticationHelper.addAuthMessageToHistory(authRequest);
        System.out.println(authRequest.getResponseBody());

    }
}
