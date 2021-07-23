package js.toy.vocabulary.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * The type Security config.
 */
/* @Configuration : 자바로 진행하는 설정 클래스에 붙이는 어노테이션으로 스프링 빈으로 만들고 스프링 프로젝트가 시작될 때 스프링 시큐리티 설정내용에 반영되도록 한다. */
@Configuration
/* @EnableWebSecurity : 스프링 시큐리티를 활성화하는 어노테이션이다. */
@EnableWebSecurity
/* WebSecurityConfigureAdapter : 스프링 시큐리티 설정관련 클래스로 커스텀 설정클래스가 이 클래스의 메소드를 오버라이딩하여 설정하여야 스프링 시큐리티에 반영된다. */
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private SecurityAuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    private SecurityAccessDeniedHandler accessDeniedHandler;

    @Bean
    public SecurityAuthenticationFilter securityAuthenticationFilter() {
        return new SecurityAuthenticationFilter();
    }

    @Bean
    public SecurityResponseAfterFilter securityResponseAfterFilter() {
        return new SecurityResponseAfterFilter();
    }


    /* AuthenticationManager 외부 사용하기 위해 */
    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    /**
     * Http 시큐리티 처리
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /* X-Frame-Options Click jacking 공격 막기 설정 */
        /* X-Frame-Options to deny 처리 */
        /* h2-console 사용하기 위해서 적용 */
        http
                .headers().frameOptions().sameOrigin();

        http.
                /* CorsFilter 필터 활성화 */
                cors().and()
                /* 세션이 아닌 JWT 토큰을 활용하기 위해 csrf disable */
                .csrf().disable()
                /* 세션 관리 X */
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                /* 예외 처리 */
                .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler) // 403(forbidden) 에러 처리를 위한 SecurityAccessDeniedHandler 등록
                    .authenticationEntryPoint(authenticationEntryPoint) // 401(unauthorized) 에러 처리를 위한 SecurityAuthenticationEntryPoint 등록
                    .and()
                /**
                * - authorizeRequests() : 인증절차에 대한 설정을 진행
                * - antMatchers() : 특정 URL 에 대해서 어떻게 인증처리를 할지 결정
                * - permitAll() : 인증 허용
                * - authenticated() : 요청내에 스프링 시큐리티 컨텍스트 내에서 인증이 완료되어야 api를 사용할 수 있다. 인증이 되지 않은 요청은 403(Forbidden)
                * .antMatchers("/api/v1/vocabulary/auth").anonymous() => 유저의 상태가 anonymous 일때 호출 가능
                **/
                /* 인증절차 시작 */
                .authorizeRequests()
                    /* .antMatchers(HttpMethod.OPTIONS, "/**").permitAll() : 크롬과 같은 브라우저에서는 실제 GET, POST 요청을 하기 전에 OPTIONS를 preflight 요청 */
                    /* 이는 실제 서버가 살아있는지를 사전에 확인하는 요청 */
                    /* Spring에서는 OPTIONS에 대한 요청을 막고 있으므로 해당 코드를 통해서 OPTIONS 요청이 왔을 때도 오류를 리턴하지 않도록 함 */
                        .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        .antMatchers("/h2-console/**").permitAll()
                        .antMatchers("/api/v1/vocabulary/permit-all").permitAll()
                        .antMatchers("/api/v1/auth/login").permitAll()

                        .antMatchers("/api/vi/vocabulary/auth").hasRole("AUTH")//.authenticated()
                        .antMatchers("/**").authenticated()
                        .anyRequest().permitAll()
                    .and()
                /* 로그인 페이지 disable */
                .formLogin().disable();

        /* 요청 전/후 호출여부를 필터자체에서 등록하는 것이 아닌 Spring Security 설정파일에서 등록 */
        http
                .addFilterBefore(securityAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        http
                .addFilterAfter(securityResponseAfterFilter(), UsernamePasswordAuthenticationFilter.class);

    }
}
