package com.adamvduke.spring.oauth;

import org.junit.BeforeClass;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class CoreOAuthSupportTest extends BaseOAuthConsumerSupportTest {

	/**
	 * Setup the Spring context for any subclasses
	 */
	@BeforeClass
	public static void setupContext() {

		context = new ClassPathXmlApplicationContext( "classpath:/core-oauth-test-spring-context.xml" );
	}
}
