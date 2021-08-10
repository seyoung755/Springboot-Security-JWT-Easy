package com.seyeong.jwt.auth;

import com.seyeong.jwt.model.User;
import com.seyeong.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// http://localhost:8080/login 요청이 올 때 동작한다.
// 그런데 formlogin을 disable하여 동작하지 않는다.
// 그래서 Filter를 통해 이 서비스를 직접 호출한다.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailService의 loadUserByUsername()");
        User user = userRepository.findByUsername(username);
        return new PrincipalDetails(user);
    }
}
