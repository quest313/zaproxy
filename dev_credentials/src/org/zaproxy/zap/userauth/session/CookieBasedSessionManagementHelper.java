/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2013 The ZAP Development Team
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.userauth.session;

import java.net.HttpCookie;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httpsessions.HttpSession;
import org.zaproxy.zap.extension.httpsessions.HttpSessionTokensSet;
import org.zaproxy.zap.userauth.session.SessionManagementMethod.UnsupportedWebSessionException;

/**
 * Helper for Cookie-based session management.
 */
public class CookieBasedSessionManagementHelper {

	private static final Logger log = Logger.getLogger(CookieBasedSessionManagementHelper.class);

	/**
	 * Modifies a message so its Request Header/Body matches the web session provided.
	 * 
	 * @param message the message
	 * @param session the session
	 */
	public static void processMessageToMatchSession(HttpMessage message, HttpSession session) {
		processMessageToMatchSession(message, message.getRequestHeader().getHttpCookies(), session);
	}

	/**
	 * Modifies a message so its Request Header/Body matches the web session provided.
	 * 
	 * @param message the message
	 * @param requestCookies a pre-computed list with the request cookies (for optimization reasons)
	 * @param session the session
	 */
	public static void processMessageToMatchSession(HttpMessage message, List<HttpCookie> requestCookies,
			HttpSession session) {

		// Make a copy of the session tokens set, as they will be modified
		HttpSessionTokensSet tokensSet = session.getTokensNames();
		Set<String> unsetSiteTokens = new LinkedHashSet<>(tokensSet.getTokensSet());

		// Iterate through the cookies in the request
		Iterator<HttpCookie> it = requestCookies.iterator();
		while (it.hasNext()) {
			HttpCookie cookie = it.next();
			String cookieName = cookie.getName();

			// If the cookie is a token
			if (tokensSet.isSessionToken(cookieName)) {
				String tokenValue = session.getTokenValue(cookieName);
				if (log.isDebugEnabled())
					log.debug("Changing value of token '" + cookieName + "' to: " + tokenValue);

				// Change it's value to the one in the active session, if any
				if (tokenValue != null) {
					cookie.setValue(tokenValue);
				}// Or delete it, if the active session does not have a token value
				else {
					it.remove();
				}

				// Remove the token from the token set so we know what tokens still have to be
				// added
				unsetSiteTokens.remove(cookieName);
			}
		}

		// Iterate through the tokens that are not present in the request and set the proper
		// value
		for (String token : unsetSiteTokens) {
			String tokenValue = session.getTokenValue(token);
			// Change it's value to the one in the active session, if any
			if (tokenValue != null) {
				if (log.isDebugEnabled())
					log.debug("Adding token '" + token + " with value: " + tokenValue);
				HttpCookie cookie = new HttpCookie(token, tokenValue);
				requestCookies.add(cookie);
			}
		}
		// Store the session in the HttpMessage for caching purpose
		message.setHttpSession(session);

		// Update the cookies in the message
		message.getRequestHeader().setCookies(requestCookies);

	}
}
