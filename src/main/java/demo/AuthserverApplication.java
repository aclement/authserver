package demo;

import java.security.KeyPair;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.ManagementServerProperties;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.SessionAttributes;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;


@Configuration
@ComponentScan
@EnableAutoConfiguration
@Controller
@SessionAttributes("authorizationRequest")
public class AuthserverApplication extends WebMvcConfigurerAdapter {

	public static void main(String[] args) {
		SpringApplication.run(AuthserverApplication.class, args);
	}
	
	@RequestMapping("/loggedin")
	@ResponseBody
	public String loggedIn() { 
		return "You are logged in";
	}
	
	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/login").setViewName("login");
		registry.addViewController("/oauth/confirm_access").setViewName("authorize");
	}

	@Configuration
	@Order(ManagementServerProperties.ACCESS_OVERRIDE_ORDER)
	protected static class LoginConfig extends WebSecurityConfigurerAdapter {
		
		@Autowired
		private AuthenticationManager authenticationManager;
		
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http.formLogin().defaultSuccessUrl("/loggedin").loginPage("/login").permitAll().and().authorizeRequests()
					.anyRequest().authenticated();
		}
		
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.parentAuthenticationManager(authenticationManager);
		}
	}

	@Configuration
	@EnableAuthorizationServer
	protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

		@Autowired
		private AuthenticationManager authenticationManager;

		@Bean
		public JwtAccessTokenConverter jwtAccessTokenConverter() {
			JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
			KeyPair keyPair = new KeyStoreKeyFactory(
					new ClassPathResource("keystore.jks"), "foobar".toCharArray())
					.getKeyPair("test");
			converter.setKeyPair(keyPair);
			return converter;
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients.inMemory()
					.withClient("demo")
					.secret("demo")
					.authorizedGrantTypes(
							"client_credentials",  // Does service registry need this one?
							"authorization_code", "refresh_token", "password")
					.scopes("openid", 
							// For eureka
							"p-service-registry.12345.read",
							"p-service-registry.12345.write",
							
							"read", "p-config-server.12345.read", // for config server
							"cloud_controller.read", "cloud_controller.admin", "cloud_controller_service_permissions.read") // for eureka server dashboard
					.autoApprove(true)
					.and()
					// Think the client id needs to start with this for eureka to recognize the client app in the right way
					.withClient("p-service-registry-demo")
					.secret("demo")
					.authorizedGrantTypes(
							"client_credentials",  // Does service registry need this one?
							"authorization_code", "refresh_token", "password")
					.scopes("openid", 
							// For eureka
							"p-service-registry.12345.read",
							"p-service-registry.12345.write",
							
							"read", "p-config-server.12345.read", // for config server
							"cloud_controller.read", "cloud_controller.admin", "cloud_controller_service_permissions.read") // for eureka server dashboard
					.autoApprove(true);

			// The original code from here:
//			clients.inMemory()
//			.withClient("acme")
//			.secret("acmesecret")
//			.authorizedGrantTypes("authorization_code", "refresh_token",
//					"password").scopes("openid");
			// From the old security server code
//			clients.inMemory()
//			.withClient("demo").secret("demo")
//			.authorizedGrantTypes("password","authorization_code","client_credentials")
//			.scopes("read","p-config-server.12345.read").autoApprove(true);
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints)
				throws Exception {
			// This instead of adjusting contextpath since not everything should be affected
			
			endpoints.pathMapping("/oauth/authorize", "/uaa/oauth/authorize");
			endpoints.pathMapping("/oauth/token", "/uaa/oauth/token");
			endpoints.pathMapping("/oauth/check_token", "/uaa/oauth/check_token");
			endpoints.pathMapping("/oauth/confirm_access", "/uaa/oauth/confirm_access");
			endpoints.pathMapping("/oauth/error", "/uaa/oauth/error");
			endpoints.pathMapping("/oauth/token_key", "/uaa/oauth/token_key");
	       
			endpoints.tokenStore(tokenStore())
	          .accessTokenConverter(accessTokenConverter())
	          .authenticationManager(authenticationManager);
			// original version:
//			endpoints.authenticationManager(authenticationManager).accessTokenConverter(
//					jwtAccessTokenConverter());
			// version from my version:
//		       endpoints.tokenStore(tokenStore())
//               .accessTokenConverter(accessTokenConverter())
//               .authenticationManager(authenticationManager);

		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer)
				throws Exception {
			oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess(
					"isAuthenticated()");
		}
		
	    @Bean
	    public TokenStore tokenStore() {
	        return new JwtTokenStore(accessTokenConverter());
	    }
	 
	    @Bean
	    public JwtAccessTokenConverter accessTokenConverter() {
	        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
	        converter.setAccessTokenConverter(new MyAccessTokenConverter());
//	        converter.setVerifier(verifier);
	        converter.setSigningKey("999");
	        converter.setVerifierKey("999");
	        return converter;
	    }
	    
	    static class MyAccessTokenConverter extends DefaultAccessTokenConverter {
	    	public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
	    		Map<String,Object> result = (Map<String, Object>) super.convertAccessToken(token, authentication);
	    		result.put("iss", "http://localhost:8989/uaa/oauth/token");
	// {exp=1487941694, user_name=foobar, authorities=[ROLE_ADMIN, ROLE_USER], jti=72220f6d-bbcd-41e2-a833-19155306a63c, client_id=demo, scope=[read, p-config-server.12345.read]}
//	    		result.put(jti, value)
	    		return result;
	    	}
	   }

	}
}
