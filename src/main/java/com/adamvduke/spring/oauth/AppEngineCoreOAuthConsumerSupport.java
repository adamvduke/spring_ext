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

import static org.springframework.security.oauth.common.OAuthCodec.oauthEncode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.URLStreamHandler;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.commons.codec.DecoderException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.common.signature.CoreOAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethod;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.consumer.InvalidOAuthRealmException;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;
import org.springframework.security.oauth.consumer.OAuthRequestFailedException;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.ProtectedResourceDetailsService;
import org.springframework.security.oauth.consumer.UnverifiedRequestTokenException;
import org.springframework.security.oauth.consumer.net.OAuthURLStreamHandlerFactory;
import org.springframework.security.oauth.consumer.nonce.NonceFactory;
import org.springframework.security.oauth.consumer.nonce.UUIDNonceFactory;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.util.StringSplitUtils;
import org.springframework.util.Assert;

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
 * requests to. Additionally removes the dependency on {@link java.net.ProxySelector} and
 * {@link java.net.Proxy} which are both restricted classes in the Google App Engine environment.
 * 
 * @author Ryan Heaton
 */
public class AppEngineCoreOAuthConsumerSupport implements OAuthConsumerSupport, InitializingBean {

	private Map <String, List <String>> validAdditionalOAuthParamNamesMap;

	private OAuthURLStreamHandlerFactory streamHandlerFactory;
	private OAuthSignatureMethodFactory signatureFactory = new CoreOAuthSignatureMethodFactory();
	private NonceFactory nonceFactory = new UUIDNonceFactory();

	private ProtectedResourceDetailsService protectedResourceDetailsService;

	private int connectionTimeout = 1000 * 60;
	private int readTimeout = 1000 * 60;

	@Override
	public void afterPropertiesSet() throws Exception {

		Assert.notNull( protectedResourceDetailsService, "A protected resource details service is required." );

		if ( streamHandlerFactory == null ) {
			try {
				streamHandlerFactory = (OAuthURLStreamHandlerFactory) Class.forName( "org.springframework.security.oauth.consumer.net.DefaultOAuthURLStreamHandlerFactory" ).newInstance();
			}
			catch ( Throwable error ) {
				throw new IllegalStateException( "A stream handler factory is required." );
			}
		}
	}

	// Inherited.
	@Override
	public OAuthConsumerToken getUnauthorizedRequestToken( String resourceId, String callback ) throws OAuthRequestFailedException {

		ProtectedResourceDetails details = getProtectedResourceDetailsService().loadProtectedResourceDetailsById( resourceId );

		URL requestTokenURL;
		try {
			requestTokenURL = new URL( details.getRequestTokenURL() );
		}
		catch ( MalformedURLException e ) {
			throw new IllegalStateException( "Malformed URL for obtaining a request token.", e );
		}

		String httpMethod = details.getRequestTokenHttpMethod();

		Map <String, String> additionalParameters = new TreeMap <String, String>();
		if ( details.isUse10a() ) {
			additionalParameters.put( OAuthConsumerParameter.oauth_callback.toString(), callback );
		}
		Map <String, String> specifiedParams = details.getAdditionalParameters();
		if ( specifiedParams != null ) {
			additionalParameters.putAll( specifiedParams );
		}
		return getTokenFromProvider( details, requestTokenURL, httpMethod, null, additionalParameters );
	}

	// Inherited.
	@Override
	public OAuthConsumerToken getAccessToken( OAuthConsumerToken requestToken, String verifier ) throws OAuthRequestFailedException {

		ProtectedResourceDetails details = getProtectedResourceDetailsService().loadProtectedResourceDetailsById( requestToken.getResourceId() );

		URL accessTokenURL;
		try {
			accessTokenURL = new URL( details.getAccessTokenURL() );
		}
		catch ( MalformedURLException e ) {
			throw new IllegalStateException( "Malformed URL for obtaining an access token.", e );
		}

		String httpMethod = details.getAccessTokenHttpMethod();

		Map <String, String> additionalParameters = new TreeMap <String, String>();
		if ( details.isUse10a() ) {
			if ( verifier == null ) {
				throw new UnverifiedRequestTokenException( "Unverified request token: " + requestToken.getValue() );
			}
			additionalParameters.put( OAuthConsumerParameter.oauth_verifier.toString(), verifier );
		}
		Map <String, String> specifiedParams = details.getAdditionalParameters();
		if ( specifiedParams != null ) {
			additionalParameters.putAll( specifiedParams );
		}
		return getTokenFromProvider( details, accessTokenURL, httpMethod, requestToken, additionalParameters );
	}

	// Inherited.
	@Override
	public InputStream readProtectedResource( URL url, OAuthConsumerToken accessToken, String httpMethod ) throws OAuthRequestFailedException {

		if ( accessToken == null ) {
			throw new OAuthRequestFailedException( "A valid access token must be supplied." );
		}

		ProtectedResourceDetails resourceDetails = getProtectedResourceDetailsService().loadProtectedResourceDetailsById( accessToken.getResourceId() );
		if ( ( !resourceDetails.isAcceptsAuthorizationHeader() ) && !"POST".equalsIgnoreCase( httpMethod ) && !"PUT".equalsIgnoreCase( httpMethod ) ) {
			throw new IllegalArgumentException( "Protected resource " + resourceDetails.getId() + " cannot be accessed with HTTP method " + httpMethod
					+ " because the OAuth provider doesn't accept the OAuth Authorization header." );
		}

		return readResource( resourceDetails, url, httpMethod, accessToken, resourceDetails.getAdditionalParameters(), null );
	}

	/**
	 * Read a resource.
	 * 
	 * @param details
	 *            The details of the resource.
	 * @param url
	 *            The URL of the resource.
	 * @param httpMethod
	 *            The http method.
	 * @param token
	 *            The token.
	 * @param additionalParameters
	 *            Any additional request parameters.
	 * @param additionalRequestHeaders
	 *            Any additional request parameters.
	 * @return The resource.
	 */
	@SuppressWarnings( "unchecked" )
	protected InputStream readResource( ProtectedResourceDetails details, URL url, String httpMethod, OAuthConsumerToken token, Map <String, String> additionalParameters,
			Map <String, String> additionalRequestHeaders ) {

		url = configureURLForProtectedAccess( url, token, details, httpMethod, additionalParameters );
		String realm = details.getAuthorizationHeaderRealm();
		boolean sendOAuthParamsInRequestBody = !details.isAcceptsAuthorizationHeader() && ( ( "POST".equalsIgnoreCase( httpMethod ) || "PUT".equalsIgnoreCase( httpMethod ) ) );
		HttpURLConnection connection = openConnection( url );

		try {
			connection.setRequestMethod( httpMethod );
		}
		catch ( ProtocolException e ) {
			throw new IllegalStateException( e );
		}

		Map <String, String> reqHeaders = details.getAdditionalRequestHeaders();
		if ( reqHeaders != null ) {
			for ( Map.Entry <String, String> requestHeader : reqHeaders.entrySet() ) {
				connection.setRequestProperty( requestHeader.getKey(), requestHeader.getValue() );
			}
		}

		if ( additionalRequestHeaders != null ) {
			for ( Map.Entry <String, String> requestHeader : additionalRequestHeaders.entrySet() ) {
				connection.setRequestProperty( requestHeader.getKey(), requestHeader.getValue() );
			}
		}

		int responseCode;
		String responseMessage;
		try {
			connection.setDoOutput( sendOAuthParamsInRequestBody );
			connection.connect();
			if ( sendOAuthParamsInRequestBody ) {
				String queryString = getOAuthQueryString( details, token, url, httpMethod, additionalParameters );
				OutputStream out = connection.getOutputStream();
				out.write( queryString.getBytes( "UTF-8" ) );
				out.flush();
				out.close();
			}
			responseCode = connection.getResponseCode();
			responseMessage = connection.getResponseMessage();
			if ( responseMessage == null ) {
				responseMessage = "Unknown Error";
			}
		}
		catch ( IOException e ) {
			throw new OAuthRequestFailedException( "OAuth connection failed.", e );
		}

		if ( responseCode >= 200 && responseCode < 300 ) {
			try {
				return connection.getInputStream();
			}
			catch ( IOException e ) {
				throw new OAuthRequestFailedException( "Unable to get the input stream from a successful response.", e );
			}
		}
		else if ( responseCode == 400 ) {
			throw new OAuthRequestFailedException( "OAuth authentication failed: " + responseMessage );
		}
		else if ( responseCode == 401 ) {
			String authHeaderValue = connection.getHeaderField( "WWW-Authenticate" );
			if ( authHeaderValue != null ) {
				Map <String, String> headerEntries = StringSplitUtils.splitEachArrayElementAndCreateMap( StringSplitUtils.splitIgnoringQuotes( authHeaderValue, ',' ), "=", "\"" );
				String requiredRealm = headerEntries.get( "realm" );
				if ( ( requiredRealm != null ) && ( !requiredRealm.equals( realm ) ) ) {
					throw new InvalidOAuthRealmException( String.format( "Invalid OAuth realm. Provider expects \"%s\", when the resource details specify \"%s\".", requiredRealm, realm ),
							requiredRealm );
				}
			}

			throw new OAuthRequestFailedException( "OAuth authentication failed: " + responseMessage );
		}
		else {
			throw new OAuthRequestFailedException( String.format( "Invalid response code %s (%s).", responseCode, responseMessage ) );
		}
	}

	/**
	 * Create a configured URL. If the HTTP method to access the resource is "POST" or "PUT" and the
	 * "Authorization" header isn't supported, then the OAuth parameters will be expected to be sent
	 * in the body of the request. Otherwise, you can assume that the given URL is ready to be used
	 * without further work.
	 * 
	 * @param url
	 *            The base URL.
	 * @param accessToken
	 *            The access token.
	 * @param httpMethod
	 *            The HTTP method.
	 * @param additionalParameters
	 *            Any additional request parameters.
	 * @return The configured URL.
	 */
	@Override
	public URL configureURLForProtectedAccess( URL url, OAuthConsumerToken accessToken, String httpMethod, Map <String, String> additionalParameters ) throws OAuthRequestFailedException {

		return configureURLForProtectedAccess( url, accessToken, getProtectedResourceDetailsService().loadProtectedResourceDetailsById( accessToken.getResourceId() ), httpMethod, additionalParameters );
	}

	/**
	 * Internal use of configuring the URL for protected access, the resource details already having
	 * been loaded.
	 * 
	 * @param url
	 *            The URL.
	 * @param requestToken
	 *            The request token.
	 * @param details
	 *            The details.
	 * @param httpMethod
	 *            The http method.
	 * @param additionalParameters
	 *            Any additional request parameters.
	 * @return The configured URL.
	 */
	protected URL configureURLForProtectedAccess( URL url, OAuthConsumerToken requestToken, ProtectedResourceDetails details, String httpMethod, Map <String, String> additionalParameters ) {

		String file;
		if ( !"POST".equalsIgnoreCase( httpMethod ) && !"PUT".equalsIgnoreCase( httpMethod ) && !details.isAcceptsAuthorizationHeader() ) {
			StringBuilder fileb = new StringBuilder( url.getPath() );
			String queryString = getOAuthQueryString( details, requestToken, url, httpMethod, additionalParameters );
			fileb.append( '?' ).append( queryString );
			file = fileb.toString();
		}
		else {
			file = url.getFile();
		}

		try {
			if ( "http".equalsIgnoreCase( url.getProtocol() ) ) {
				URLStreamHandler streamHandler = getStreamHandlerFactory().getHttpStreamHandler( details, requestToken, this, httpMethod, additionalParameters );
				return new URL( url.getProtocol(), url.getHost(), url.getPort(), file, streamHandler );
			}
			else if ( "https".equalsIgnoreCase( url.getProtocol() ) ) {
				URLStreamHandler streamHandler = getStreamHandlerFactory().getHttpsStreamHandler( details, requestToken, this, httpMethod, additionalParameters );
				return new URL( url.getProtocol(), url.getHost(), url.getPort(), file, streamHandler );
			}
			else {
				throw new OAuthRequestFailedException( "Unsupported OAuth protocol: " + url.getProtocol() );
			}
		}
		catch ( MalformedURLException e ) {
			throw new IllegalStateException( e );
		}
	}

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

	/**
	 * Finds a valid header value that is valid for the OAuth header.
	 * 
	 * @param paramValues
	 *            The possible values for the oauth header.
	 * @return The selected value, or null if none were found.
	 */
	protected String findValidHeaderValue( Set <CharSequence> paramValues ) {

		String selectedValue = null;
		if ( paramValues != null && !paramValues.isEmpty() ) {
			CharSequence value = paramValues.iterator().next();
			if ( !( value instanceof QueryParameterValue ) ) {
				selectedValue = value.toString();
			}
		}
		return selectedValue;
	}

	// Inherited.
	@Override
	public String getOAuthQueryString( ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url, String httpMethod, Map <String, String> additionalParameters ) {

		Map <String, Set <CharSequence>> oauthParams = loadOAuthParameters( details, url, accessToken, httpMethod, additionalParameters );

		StringBuilder queryString = new StringBuilder();
		if ( details.isAcceptsAuthorizationHeader() ) {
			// if the resource accepts the auth header, remove any parameters that will go in the
			// header (don't pass them redundantly in the query string).
			for ( OAuthConsumerParameter oauthParam : OAuthConsumerParameter.values() ) {
				oauthParams.remove( oauthParam.toString() );
			}

			if ( additionalParameters != null ) {
				for ( String additionalParam : additionalParameters.keySet() ) {
					oauthParams.remove( additionalParam );
				}
			}
		}

		Iterator <String> parametersIt = oauthParams.keySet().iterator();
		while ( parametersIt.hasNext() ) {
			String parameter = parametersIt.next();
			queryString.append( parameter );
			Set <CharSequence> values = oauthParams.get( parameter );
			if ( values != null ) {
				Iterator <CharSequence> valuesIt = values.iterator();
				while ( valuesIt.hasNext() ) {
					CharSequence parameterValue = valuesIt.next();
					if ( parameterValue != null ) {
						queryString.append( '=' ).append( parameterValue );
					}
					if ( valuesIt.hasNext() ) {
						queryString.append( '&' ).append( parameter );
					}
				}
			}
			if ( parametersIt.hasNext() ) {
				queryString.append( '&' );
			}
		}

		return queryString.toString();
	}

	/**
	 * Get the consumer token with the given parameters and URL. The determination of whether the
	 * retrieved token is an access token depends on whether a request token is provided.
	 * 
	 * @param details
	 *            The resource details.
	 * @param tokenURL
	 *            The token URL.
	 * @param httpMethod
	 *            The http method.
	 * @param requestToken
	 *            The request token, or null if none.
	 * @param additionalParameters
	 *            The additional request parameter.
	 * @return The token.
	 */
	protected OAuthConsumerToken getTokenFromProvider( ProtectedResourceDetails details, URL tokenURL, String httpMethod, OAuthConsumerToken requestToken, Map <String, String> additionalParameters ) {

		boolean isAccessToken = requestToken != null;
		if ( !isAccessToken ) {
			// create an empty token to make a request for a new unauthorized request token.
			requestToken = new OAuthConsumerToken();
		}

		TreeMap <String, String> requestHeaders = new TreeMap <String, String>();
		if ( "POST".equalsIgnoreCase( httpMethod ) ) {
			requestHeaders.put( "Content-Type", "application/x-www-form-urlencoded" );
		}
		InputStream inputStream = readResource( details, tokenURL, httpMethod, requestToken, additionalParameters, requestHeaders );
		String tokenInfo;
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			int len = inputStream.read( buffer );
			while ( len >= 0 ) {
				out.write( buffer, 0, len );
				len = inputStream.read( buffer );
			}

			tokenInfo = new String( out.toByteArray(), "UTF-8" );
		}
		catch ( IOException e ) {
			throw new OAuthRequestFailedException( "Unable to read the token.", e );
		}

		StringTokenizer tokenProperties = new StringTokenizer( tokenInfo, "&" );
		Map <String, String> tokenPropertyValues = new TreeMap <String, String>();
		while ( tokenProperties.hasMoreElements() ) {
			try {
				String tokenProperty = (String) tokenProperties.nextElement();
				int equalsIndex = tokenProperty.indexOf( '=' );
				if ( equalsIndex > 0 ) {
					String propertyName = OAuthCodec.oauthDecode( tokenProperty.substring( 0, equalsIndex ) );
					String propertyValue = OAuthCodec.oauthDecode( tokenProperty.substring( equalsIndex + 1 ) );
					tokenPropertyValues.put( propertyName, propertyValue );
				}
				else {
					tokenProperty = OAuthCodec.oauthDecode( tokenProperty );
					tokenPropertyValues.put( tokenProperty, null );
				}
			}
			catch ( DecoderException e ) {
				throw new OAuthRequestFailedException( "Unable to decode token parameters." );
			}
		}

		String tokenValue = tokenPropertyValues.remove( OAuthProviderParameter.oauth_token.toString() );
		if ( tokenValue == null ) {
			throw new OAuthRequestFailedException( "OAuth provider failed to return a token." );
		}

		String tokenSecret = tokenPropertyValues.remove( OAuthProviderParameter.oauth_token_secret.toString() );
		if ( tokenSecret == null ) {
			throw new OAuthRequestFailedException( "OAuth provider failed to return a token secret." );
		}

		OAuthConsumerToken consumerToken = new OAuthConsumerToken();
		consumerToken.setValue( tokenValue );
		consumerToken.setSecret( tokenSecret );
		consumerToken.setResourceId( details.getId() );
		consumerToken.setAccessToken( isAccessToken );
		if ( !tokenPropertyValues.isEmpty() ) {
			consumerToken.setAdditionalParameters( tokenPropertyValues );
		}
		return consumerToken;
	}

	/**
	 * Loads the OAuth parameters for the given resource at the given URL and the given token. These
	 * parameters include any query parameters on the URL since they are included in the signature.
	 * The oauth parameters are NOT encoded.
	 * 
	 * @param details
	 *            The resource details.
	 * @param requestURL
	 *            The request URL.
	 * @param requestToken
	 *            The request token.
	 * @param httpMethod
	 *            The http method.
	 * @param additionalParameters
	 *            Additional oauth parameters (outside of the core oauth spec).
	 * @return The parameters.
	 */
	protected Map <String, Set <CharSequence>> loadOAuthParameters( ProtectedResourceDetails details, URL requestURL, OAuthConsumerToken requestToken, String httpMethod,
			Map <String, String> additionalParameters ) {

		Map <String, Set <CharSequence>> oauthParams = new TreeMap <String, Set <CharSequence>>();

		if ( additionalParameters != null ) {
			for ( Map.Entry <String, String> additionalParam : additionalParameters.entrySet() ) {
				Set <CharSequence> values = oauthParams.get( additionalParam.getKey() );
				if ( values == null ) {
					values = new HashSet <CharSequence>();
					oauthParams.put( additionalParam.getKey(), values );
				}
				if ( additionalParam.getValue() != null ) {
					values.add( additionalParam.getValue() );
				}
			}
		}

		String query = requestURL.getQuery();
		if ( query != null ) {
			StringTokenizer queryTokenizer = new StringTokenizer( query, "&" );
			while ( queryTokenizer.hasMoreElements() ) {
				String token = (String) queryTokenizer.nextElement();
				CharSequence value = null;
				int equalsIndex = token.indexOf( '=' );
				if ( equalsIndex < 0 ) {
					token = urlDecode( token );
				}
				else {
					value = new QueryParameterValue( urlDecode( token.substring( equalsIndex + 1 ) ) );
					token = urlDecode( token.substring( 0, equalsIndex ) );
				}

				Set <CharSequence> values = oauthParams.get( token );
				if ( values == null ) {
					values = new HashSet <CharSequence>();
					oauthParams.put( token, values );
				}
				if ( value != null ) {
					values.add( value );
				}
			}
		}

		String tokenSecret = requestToken == null ? null : requestToken.getSecret();
		String nonce = getNonceFactory().generateNonce();
		oauthParams.put( OAuthConsumerParameter.oauth_consumer_key.toString(), Collections.singleton( (CharSequence) details.getConsumerKey() ) );
		if ( ( requestToken != null ) && ( requestToken.getValue() != null ) ) {
			oauthParams.put( OAuthConsumerParameter.oauth_token.toString(), Collections.singleton( (CharSequence) requestToken.getValue() ) );
		}

		oauthParams.put( OAuthConsumerParameter.oauth_nonce.toString(), Collections.singleton( (CharSequence) nonce ) );
		oauthParams.put( OAuthConsumerParameter.oauth_signature_method.toString(), Collections.singleton( (CharSequence) details.getSignatureMethod() ) );
		oauthParams.put( OAuthConsumerParameter.oauth_timestamp.toString(), Collections.singleton( (CharSequence) String.valueOf( System.currentTimeMillis() / 1000 ) ) );
		oauthParams.put( OAuthConsumerParameter.oauth_version.toString(), Collections.singleton( (CharSequence) "1.0" ) );
		String signatureBaseString = getSignatureBaseString( oauthParams, requestURL, httpMethod );
		OAuthSignatureMethod signatureMethod = getSignatureFactory().getSignatureMethod( details.getSignatureMethod(), details.getSharedSecret(), tokenSecret );
		String signature = signatureMethod.sign( signatureBaseString );
		oauthParams.put( OAuthConsumerParameter.oauth_signature.toString(), Collections.singleton( (CharSequence) signature ) );
		return oauthParams;
	}

	/**
	 * URL-encode a value.
	 * 
	 * @param value
	 *            The value to encode.
	 * @return The URL-encoded value.
	 */
	protected String urlEncode( String value ) {

		try {
			return URLEncoder.encode( value, "UTF-8" );
		}
		catch ( UnsupportedEncodingException e ) {
			throw new RuntimeException( e );
		}
	}

	/**
	 * URL-decode a token.
	 * 
	 * @param token
	 *            The token to URL-decode.
	 * @return The decoded token.
	 */
	protected String urlDecode( String token ) {

		try {
			return URLDecoder.decode( token, "utf-8" );
		}
		catch ( UnsupportedEncodingException e ) {
			throw new RuntimeException( e );
		}
	}

	/**
	 * Open a connection to the given URL.
	 * 
	 * @param requestTokenURL
	 *            The request token URL.
	 * @return The HTTP URL connection.
	 */
	protected HttpURLConnection openConnection( URL requestTokenURL ) {

		try {
			HttpURLConnection connection = (HttpURLConnection) requestTokenURL.openConnection();
			connection.setConnectTimeout( getConnectionTimeout() );
			connection.setReadTimeout( getReadTimeout() );
			return connection;
		}
		catch ( IOException e ) {
			throw new OAuthRequestFailedException( "Failed to open an OAuth connection.", e );
		}
	}

	/**
	 * Get the signature base string for the specified parameters. It is presumed the parameters are
	 * NOT OAuth-encoded.
	 * 
	 * @param oauthParams
	 *            The parameters (NOT oauth-encoded).
	 * @param requestURL
	 *            The request URL.
	 * @param httpMethod
	 *            The http method.
	 * @return The signature base string.
	 */
	protected String getSignatureBaseString( Map <String, Set <CharSequence>> oauthParams, URL requestURL, String httpMethod ) {

		TreeMap <String, TreeSet <String>> sortedParameters = new TreeMap <String, TreeSet <String>>();

		for ( Map.Entry <String, Set <CharSequence>> param : oauthParams.entrySet() ) {
			// first encode all parameter names and values (spec section 9.1)
			String key = oauthEncode( param.getKey() );

			// add the encoded parameters sorted according to the spec.
			TreeSet <String> sortedValues = sortedParameters.get( key );
			if ( sortedValues == null ) {
				sortedValues = new TreeSet <String>();
				sortedParameters.put( key, sortedValues );
			}

			for ( CharSequence value : param.getValue() ) {
				sortedValues.add( oauthEncode( value.toString() ) );
			}
		}

		// now concatenate them into a single query string according to the spec.
		StringBuilder queryString = new StringBuilder();
		Iterator <Map.Entry <String, TreeSet <String>>> sortedIt = sortedParameters.entrySet().iterator();
		while ( sortedIt.hasNext() ) {
			Map.Entry <String, TreeSet <String>> sortedParameter = sortedIt.next();
			for ( String parameterValue : sortedParameter.getValue() ) {
				if ( parameterValue == null ) {
					parameterValue = "";
				}

				queryString.append( sortedParameter.getKey() ).append( '=' ).append( parameterValue );
				if ( sortedIt.hasNext() ) {
					queryString.append( '&' );
				}
			}
		}

		StringBuilder url = new StringBuilder( requestURL.getProtocol().toLowerCase() ).append( "://" ).append( requestURL.getHost().toLowerCase() );
		if ( ( requestURL.getPort() >= 0 ) && ( requestURL.getPort() != requestURL.getDefaultPort() ) ) {
			url.append( ":" ).append( requestURL.getPort() );
		}
		url.append( requestURL.getPath() );

		return new StringBuilder( httpMethod.toUpperCase() ).append( '&' ).append( oauthEncode( url.toString() ) ).append( '&' ).append( oauthEncode( queryString.toString() ) ).toString();
	}

	public void setValidAdditionalOAuthParamNamesMap( Map <String, List <String>> validAdditionalOAuthParamNamesMap ) {

		this.validAdditionalOAuthParamNamesMap = validAdditionalOAuthParamNamesMap;
	}

	/**
	 * The protected resource details service.
	 * 
	 * @return The protected resource details service.
	 */
	public ProtectedResourceDetailsService getProtectedResourceDetailsService() {

		return protectedResourceDetailsService;
	}

	/**
	 * The protected resource details service.
	 * 
	 * @param protectedResourceDetailsService
	 *            The protected resource details service.
	 */
	@Autowired
	public void setProtectedResourceDetailsService( ProtectedResourceDetailsService protectedResourceDetailsService ) {

		this.protectedResourceDetailsService = protectedResourceDetailsService;
	}

	/**
	 * The URL stream handler factory for connections to an OAuth resource.
	 * 
	 * @return The URL stream handler factory for connections to an OAuth resource.
	 */
	public OAuthURLStreamHandlerFactory getStreamHandlerFactory() {

		return streamHandlerFactory;
	}

	/**
	 * The URL stream handler factory for connections to an OAuth resource.
	 * 
	 * @param streamHandlerFactory
	 *            The URL stream handler factory for connections to an OAuth resource.
	 */
	@Autowired( required = false )
	public void setStreamHandlerFactory( OAuthURLStreamHandlerFactory streamHandlerFactory ) {

		this.streamHandlerFactory = streamHandlerFactory;
	}

	/**
	 * The nonce factory.
	 * 
	 * @return The nonce factory.
	 */
	public NonceFactory getNonceFactory() {

		return nonceFactory;
	}

	/**
	 * The nonce factory.
	 * 
	 * @param nonceFactory
	 *            The nonce factory.
	 */
	@Autowired( required = false )
	public void setNonceFactory( NonceFactory nonceFactory ) {

		this.nonceFactory = nonceFactory;
	}

	/**
	 * The signature factory to use.
	 * 
	 * @return The signature factory to use.
	 */
	public OAuthSignatureMethodFactory getSignatureFactory() {

		return signatureFactory;
	}

	/**
	 * The signature factory to use.
	 * 
	 * @param signatureFactory
	 *            The signature factory to use.
	 */
	@Autowired( required = false )
	public void setSignatureFactory( OAuthSignatureMethodFactory signatureFactory ) {

		this.signatureFactory = signatureFactory;
	}

	/**
	 * The connection timeout (default 60 seconds).
	 * 
	 * @return The connection timeout.
	 */
	public int getConnectionTimeout() {

		return connectionTimeout;
	}

	/**
	 * The connection timeout.
	 * 
	 * @param connectionTimeout
	 *            The connection timeout.
	 */
	public void setConnectionTimeout( int connectionTimeout ) {

		this.connectionTimeout = connectionTimeout;
	}

	/**
	 * The read timeout (default 60 seconds).
	 * 
	 * @return The read timeout.
	 */
	public int getReadTimeout() {

		return readTimeout;
	}

	/**
	 * The read timeout.
	 * 
	 * @param readTimeout
	 *            The read timeout.
	 */
	public void setReadTimeout( int readTimeout ) {

		this.readTimeout = readTimeout;
	}

	/**
	 * Marker class for an oauth parameter value that is a query parameter and should therefore not
	 * be included in the authorization header.
	 */
	public static class QueryParameterValue implements CharSequence {

		private final String value;

		public QueryParameterValue( String value ) {

			this.value = value;
		}

		@Override
		public int length() {

			return this.value.length();
		}

		@Override
		public char charAt( int index ) {

			return this.value.charAt( index );
		}

		@Override
		public CharSequence subSequence( int start, int end ) {

			return this.value.subSequence( start, end );
		}

		@Override
		public String toString() {

			return this.value;
		}

		@Override
		public int hashCode() {

			return this.value.hashCode();
		}

		@Override
		public boolean equals( Object obj ) {

			return this.value.equals( obj );
		}
	}
}
