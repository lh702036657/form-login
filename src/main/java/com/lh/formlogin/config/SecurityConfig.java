package com.lh.formlogin.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.PrintWriter;

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
                .successHandler((req, resp, authentication) ->{     //登录成功的回调
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString(authentication.getPrincipal())); //放回当前登录的用户信息
                    writer.flush();
                    writer.close();
                } )
                .failureHandler(((req, resp, exception) -> {        //登录失败的回调
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString(exception.getMessage())); //放回当前登录的用户信息
                    writer.flush();
                    writer.close();
                }))
//                .successForwardUrl("/success")//重定向到指定的页面
//                .defaultSuccessUrl("/success")  //重载进行跳转
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout")           //注销接口路径
                .logoutSuccessHandler(((req, resp, authentication) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString("注销登录成功")); //放回当前登录的用户信息
                    writer.flush();
                    writer.close();
                }))
                .permitAll()
                .and()
                .csrf()
                .disable()
                .exceptionHandling()
                .authenticationEntryPoint((req, resp, exception) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter writer = resp.getWriter();
                    writer.write(new ObjectMapper().writeValueAsString("尚未登录,请登录")); //放回当前登录的用户信息
                    writer.flush();
                    writer.close();
                });
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/js/**","/css/**","/images/**");    //开放路径
    }
}
