package com.mausoft.security.oauth2.config;

import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.InMemoryUserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer.UserDetailsBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
@Configuration
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class WebSecurity extends WebSecurityConfigurerAdapter {
	
	/*@Bean
	CorsConfigurationSource corsConfigurationSource() {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
		return source;
	}*/

	
	@Override
    @Bean(name="authenticationManagerBean")
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
	
	@Override
	protected void configure(AuthenticationManagerBuilder authManagerBuilder) throws Exception {
		System.out.println("WebSecurity#configure(AuthenticationManagerBuilder)");
		UserDetailsBuilder userBuilder = null;
		InMemoryUserDetailsManagerConfigurer<AuthenticationManagerBuilder> configurer = null;
		
		//authManagerBuilder.parentAuthenticationManager(authenticationManager);
		
		
		configurer = authManagerBuilder.inMemoryAuthentication();
		configurer.passwordEncoder(new BCryptPasswordEncoder(12));
		
		userBuilder = configurer.withUser("admin@admin.com");
		
		userBuilder.password(new BCryptPasswordEncoder(12).encode("Password123")).authorities(new GrantedAuthority[]{() -> "ROLE_ADMIN"});
		
		userBuilder = configurer.withUser("testUser");
		
		userBuilder.password("temp").authorities(new GrantedAuthority[] {() -> "ROLE_REQUESTOR"});
		
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		System.out.println("WebSecurity#configure(HttpSecurity)");
		//http.cors().and().csrf().disable().authorizeRequests()
		//	.antMatchers(HttpMethod.GET, "/", "/index.html", "/css/**/*", "/images/**/*.css", "/js/**/*", "*.ico").permitAll()
		//	.and().authorizeRequests()
		//	.antMatchers(HttpMethod.POST, "/api/login").permitAll()
		//	.and().authorizeRequests()
		//	.antMatchers(HttpMethod.GET, "/api/data/exchange/symbols").authenticated()
		//	.anyRequest().authenticated()
		//	.and()
		//	.formLogin().permitAll();;
			/*.and()
			.addFilter(new JwtAuthenticationFilter(authenticationManager()))
			.addFilter(new JwtAuthorizationFilter(authenticationManager()));*/
		
		http
		.cors().and()
		.csrf().disable()
        .formLogin().disable() // disable form authentication
        .anonymous().disable() // disable anonymous user
        .httpBasic().disable()
        // restricting access to authenticated users
        .authorizeRequests().anyRequest().authenticated();
	}
	
	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/**", config);
        
        return new CorsFilter(source);
	}
}