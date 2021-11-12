package com.lh.formlogin.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
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
                .roles("admin")
                .and()
                .withUser("lh")
                .password("123")
                .roles("user");
    }

    /**
     * 配置角色继承
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return hierarchy;
    }

/*    @Override
    @Bean
*//* 也可以使用 JdbcUserDetailsManager
    和configure配置同理，配置用户名称以及密码和角色 Spring Security 支持多种数据源,如内存,数据库,LDAP,这些不同来源的数据都被共同封装为一个
    UserDetailService接口,实现了该接口的对象都可以作为认证数据源。*//*
    protected UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("lh").password("123").roles("admin").build());
        return manager;
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")  //访问/admin的路径需要拥有admin权限    匹配路径的规则是从上往下
                .antMatchers("/user/**").hasRole("user")    //和admin同理
                .anyRequest().authenticated()                           //剩余其他格式的请求路径，只需要登录后就可以访问 authenticated不可以放在第一行
                .and()
                .formLogin()
//                .loginPage("/login.html")       //设置登录地址,如果不设置登录接口地址,默认也是使用该地址
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
