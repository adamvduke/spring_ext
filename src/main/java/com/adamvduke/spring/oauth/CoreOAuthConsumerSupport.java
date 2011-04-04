/*
 * Copyright 2008 Web Cohesion
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

package com.adamvduke.spring.oauth;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;

/**
 * An extension to {@link org.springframework.security.oauth.consumer.CoreOAuthConsumerSupport} that
 * fixes a bug in the getAuthorizationHeader method. The original logic appends all key/value pairs
 * in the additionalParameters map to the Authorization header. From my understanding of the oauth
 * spec, the only parameters that should be included in the Authorization header, are the parameters
 * specific to the authorization of the request. However, in order to compute the signature for any
 * particular request, other parameters e.g. parameters that will be passed as html form encoded
 * parameters in the body of the request, those key/value pairs must also be included in the
 * additionalParameters, but excluded from the Authorization header. This implementation adds a
 * Map<String,List<String>> to allow a user to supply a list of acceptable additional parameters
 * that can be used in the Authorization header per provider that the user wishes to send signed
 * requests to.
 * 
 * @author Ryan Heaton
 */
public class CoreOAuthConsumerSupport extends org.springframework.security.oauth.consumer.CoreOAuthConsumerSupport {

	private Map <String, List <String>> validAdditionalOAuthParamNamesMap;

	@Override
	public String getAuthorizationHeader( ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url, String httpMethod, Map <String, String> additionalParameters ) {

		if ( !details.isAcceptsAuthorizationHeader() ) {
			return null;
		}
		else {
			Map <String, Set <CharSequence>> oauthParams = loadOAuthParameters( details, url, accessToken, httpMethod, additionalParameters );
			String realm = details.getAuthorizationHeaderRealm();

			StringBuilder builder = new StringBuilder( "OAuth " );
			boolean writeComma = false;
			if ( realm != null ) { // realm is optional.
				builder.append( "realm=\"" ).append( realm ).append( '"' );
				writeComma = true;
			}

			for ( Map.Entry <String, Set <CharSequence>> paramValuesEntry : oauthParams.entrySet() ) {
				String key = paramValuesEntry.getKey();

				List <String> validAdditionalOAuthParamNames = null;
				if ( validAdditionalOAuthParamNamesMap != null ) {
					validAdditionalOAuthParamNames = validAdditionalOAuthParamNamesMap.get( details.getId() );
				}

				// filtering out the invalid parameters from the authorization header
				if ( !key.startsWith( "oauth_" ) && ( validAdditionalOAuthParamNames != null && !validAdditionalOAuthParamNames.contains( key ) ) ) {
					continue;
				}
				Set <CharSequence> paramValues = paramValuesEntry.getValue();
				CharSequence paramValue = findValidHeaderValue( paramValues );
				if ( paramValue != null ) {
					if ( writeComma ) {
						builder.append( ", " );
					}

					builder.append( paramValuesEntry.getKey() ).append( "=\"" ).append( OAuthCodec.oauthEncode( paramValue.toString() ) ).append( '"' );
					writeComma = true;
				}
			}

			return builder.toString();
		}
	}

	public void setValidAdditionalOAuthParamNamesMap( Map <String, List <String>> validAdditionalOAuthParamNamesMap ) {

		this.validAdditionalOAuthParamNamesMap = validAdditionalOAuthParamNamesMap;
	}
}
