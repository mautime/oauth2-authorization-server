package com.mausoft.security.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@EnableAuthorizationServer
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter{
	
	@Autowired
	@Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;
	
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		System.out.println("AuthorizationServer#configure(AuthorizationServerSecurityConfigurer)");
		
		security.tokenKeyAccess("permitAll()")
			.checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer client) throws Exception {
		System.out.println("AuthorizationServer#configure(ClientDetailsServiceConfigurer)");
		client.inMemory()
			.withClient("InversionManagerClientSimple")
			.secret("supersecret")
			.authorizedGrantTypes("password", "refresh_token")
			//.accessTokenValiditySeconds(60*30)
			.authorities("ROLE_TRUSTED_CLIENT")
			.scopes("resource-server-read", "resource-server-write")
			.resourceIds("resource");
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		System.out.println("AuthorizationServer#configure(AuthorizationServerEndpointsConfigurer)");
		//endpoints.prefix("/api");
		
		endpoints.authenticationManager(authenticationManager)
			.tokenServices(tokenServices())
			.tokenStore(jwtTokenStore())
			.tokenEnhancer(jwtTokenConverter());
	}
	
	@Bean
	public JwtAccessTokenConverter jwtTokenConverter() {
		JwtAccessTokenConverter converter = null;
		converter = new JwtAccessTokenConverter();
		
		converter.setSigningKey("$p4h9j\\>AbZKne5A");
		
		return converter;
	}
	
	@Bean
	public TokenStore jwtTokenStore() {
		return new JwtTokenStore(jwtTokenConverter());
	}
	
	@Bean
	@Primary
	public DefaultTokenServices tokenServices() {
		DefaultTokenServices dts = null;
		
		dts = new DefaultTokenServices();
		
		dts.setSupportRefreshToken(true);
		dts.setTokenStore(jwtTokenStore());
		dts.setTokenEnhancer(jwtTokenConverter());
		dts.setAccessTokenValiditySeconds(60 * 30);
		dts.setRefreshTokenValiditySeconds(60 * 30 + (10 * 30));
		
		return dts;
	}
}