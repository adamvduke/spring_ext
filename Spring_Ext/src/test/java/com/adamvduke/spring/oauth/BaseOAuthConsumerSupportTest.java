package com.adamvduke.spring.oauth;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;
import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.ProtectedResourceDetailsService;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;

public class BaseOAuthConsumerSupportTest {

	protected static ClassPathXmlApplicationContext context;
	protected OAuthConsumerSupport support;
	protected ProtectedResourceDetailsService detailsService;
	protected ProtectedResourceDetails details;
	protected URL aUrl;

	@Before
	public void setup() throws Exception {

		support = (OAuthConsumerSupport) context.getBean( "oauthConsumerSupport" );
		detailsService = (ProtectedResourceDetailsService) context.getBean( "resourceDetailsService" );
		details = detailsService.loadProtectedResourceDetailsById( "test" );
		aUrl = new URL( "http://something.com" );
	}

	@Test
	public void shouldGetAuthorizationHeader() {

		OAuthConsumerToken accessToken = getAccessToken();

		String authHeader = support.getAuthorizationHeader( details, accessToken, aUrl, "POST", null );
		Assert.assertNotNull( authHeader );
	}

	@Test
	public void shouldGetAuthorizationHeaderWithValidExtraParams() throws Exception {

		OAuthConsumerToken accessToken = getAccessToken();

		Map <String, String> additionalParams = new HashMap <String, String>();
		additionalParams.put( "scope", "google_calendars" );
		additionalParams.put( "xoauth_displayname", "my_cool_app" );

		String authHeader = support.getAuthorizationHeader( details, accessToken, aUrl, "POST", additionalParams );
		Assert.assertTrue( authHeader.contains( "scope=\"google_calendars\"" ) );
		Assert.assertTrue( authHeader.contains( "xoauth_displayname=\"my_cool_app\"" ) );
	}

	@Test
	public void shouldGetAuthorizationHeaderWithValidExtraParamsAndExcludeJunkParams() throws Exception {

		OAuthConsumerToken accessToken = getAccessToken();

		Map <String, String> additionalParams = new HashMap <String, String>();
		additionalParams.put( "scope", "google_calendars" );
		additionalParams.put( "xoauth_displayname", "my_cool_app" );
		additionalParams.put( "junk_param_1", "junk_param_1_value" );
		additionalParams.put( "junk_param_2", "junk_param_2_value" );

		String authHeader = support.getAuthorizationHeader( details, accessToken, aUrl, "POST", additionalParams );
		Assert.assertTrue( authHeader.contains( "scope=\"google_calendars\"" ) );
		Assert.assertTrue( authHeader.contains( "xoauth_displayname=\"my_cool_app\"" ) );
		Assert.assertFalse( authHeader.contains( "junk_param_1=\"junk_param_1_value\"" ) );
		Assert.assertFalse( authHeader.contains( "junk_param_2=\"junk_param_2_value\"" ) );
	}

	private OAuthConsumerToken getAccessToken() {

		OAuthConsumerToken accessToken = new OAuthConsumerToken();
		accessToken.setAccessToken( true );
		accessToken.setResourceId( "test" );
		accessToken.setValue( "a_value" );
		accessToken.setSecret( "a_secret" );
		return accessToken;
	}

}
