// 
// Decompiled by Procyon v0.5.36
// 

package tenb.logforge;

import org.springframework.context.annotation.Bean;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class LogForgeSec extends WebSecurityConfigurerAdapter
{
    @Value("${app.admin}")
    public String username;
    @Value("${app.password}")
    public String password;
    
    protected void configure(final HttpSecurity http) throws Exception {
        ((HttpSecurity)((HttpSecurity)((FormLoginConfigurer)((FormLoginConfigurer)((FormLoginConfigurer)((FormLoginConfigurer)((HttpSecurity)((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)http.authorizeRequests().antMatchers(new String[] { "/dashboard**" })).authenticated().anyRequest()).permitAll().and()).formLogin().loginPage("/login").permitAll()).defaultSuccessUrl("/dashboard")).failureUrl("/errpg?dbgmsg=err.401")).permitAll()).and()).logout().permitAll().and()).exceptionHandling().accessDeniedPage("/errpg?dbgmsg=err.401");
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        System.out.println(this.username);
        final UserDetails user = User.withDefaultPasswordEncoder().username(this.username).password(this.password).roles(new String[] { "USER" }).build();
        return (UserDetailsService)new InMemoryUserDetailsManager(new UserDetails[] { user });
    }
}
