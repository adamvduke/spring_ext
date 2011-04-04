package com.adamvduke.spring.oauth;

import org.junit.BeforeClass;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class AppEngineOAuthSupportTest extends BaseOAuthConsumerSupportTest {

	/**
	 * Setup the Spring context for any subclasses
	 */
	@BeforeClass
	public static void setupContext() {

		context = new ClassPathXmlApplicationContext( "classpath:/appEngine-test-oauth-spring-context.xml" );
	}
}
