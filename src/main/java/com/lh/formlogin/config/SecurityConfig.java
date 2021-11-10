package com.lh.formlogin.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 代码的配置高于配置文件,会覆盖yml里面的user和password
     * 配置用户名和密码
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("java")
                .password("123")
                .roles("admin");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login.html")       //设置登录地址,如果不设置登录接口地址,默认也是使用该地址
                .loginProcessingUrl("/doLogin") //设置登录接口地址
                .usernameParameter("name")      //登录时传递过来的参数名(用户名)
                .passwordParameter("pwd")       //登录时传递过来的参数名(密码)
//                .successForwardUrl("/success")//重定向到指定的页面
                .defaultSuccessUrl("/success")  //重载进行跳转
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")           //注销接口路径
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout","POST"))  //不仅可以修改注销接口路径,还可以修改请求方式
                .and()
                .csrf()
                .disable();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**","/css/**","/images/**");    //开放路径
    }
}
