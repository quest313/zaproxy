package org.zaproxy.zap.authentication;

import org.junit.Test;

public class OAuthHelperTest {

    public static final String AUTH_URL = "https://account.box.com/api/oauth2/authorize?response_type=code&client_id=" +
            "y8zfuvl1krh22s5mjw1lrjx5p6an1gsk&state=security_token%3DKnhMJatFipTAnM0nHlZA\n";

    @Test
    public void shouldAuthenticate() throws Exception {
        OAuthHelper.authenticate(AUTH_URL);



    }

}