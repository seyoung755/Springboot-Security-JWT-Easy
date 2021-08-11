package com.seyeong.jwt.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.seyeong.jwt.auth.PrincipalDetails;
import com.seyeong.jwt.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티의 UsernamePasswordAuthenticationFilter는 /login 요청을 했을 때 동작한다.
// 1.username, password 받아서

// 2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시도를 하면
// PrincipalDetailsService가 호출된다. loadUserByUsername() 함수 실행됨.

// 3. PrincipalDetails를 세션에 담고 -> 권한관리를 위함 -> 즉, 완벽한 STATELESS를 위해서는 직접 권한관리까지 구현해줘야 한다. ㅌㅌ

// 4. JWT 토큰을 만들어서 응답해주면 된다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도 중");


        try {
//            BufferedReader br = request.getReader();  // username과 password가 담겨있다.
//            String input = null;
//
//            while((input = br.readLine()) != null) {
//                System.out.println(input);
//            }

            ObjectMapper om = new ObjectMapper(); // JSON 파싱
            User user = om.readValue(request.getInputStream(), User.class); // User object에 담아준다.
            System.out.println(user);

            // 로그인 시 발급되는 토큰 수동으로 설정
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 함수가 실행됨.
            // DB에 있는 username과 password가 일치하여 인증이 완료되면 authentication이 리턴됨.
            // authentication 객체 내에 로그인 정보가 담김.
            Authentication authentication =
                    authenticationManager.authenticate(authenticationToken);


            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료됨" + principalDetails.getUser().getUsername());

            // authentication 객체가 session 영역에 저장됨. => 로그인이 완료되었다는 뜻.
            // 리턴하여 세션에 저장하는 이유는 권한 관리를 편하게 하려고.
            // JWT 사용 시에는 세션을 만들 이유가 원래는 없다.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("=========================");

        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되면 실행됨.
    // JWT 토큰을 만들어서 request요청한 사용자에게 response해주면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA는 아니고 Hash암호 방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000*10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization" , "Bearer "+jwtToken);
        
    }
}
