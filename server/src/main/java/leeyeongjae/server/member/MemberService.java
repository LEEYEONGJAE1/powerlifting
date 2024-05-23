package leeyeongjae.server.member;

import leeyeongjae.server.jwt.JwtTokenProvider;
import leeyeongjae.server.domain.jwt.JwtToken;
import leeyeongjae.server.jwt.domain.JwtRepository;
import leeyeongjae.server.jwt.domain.RefreshToken;
import leeyeongjae.yryrserver.member.domain.MemberRepository;
import leeyeongjae.yryrserver.member.domain.dto.MemberCreateResponseDto;
import leeyeongjae.yryrserver.member.domain.dto.SignUpDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class MemberService{
    private final MemberRepository memberRepository;
    private final JwtRepository jwtRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    @Transactional
    public JwtToken signIn(String username, String password) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        JwtToken jwtToken = jwtTokenProvider.generateToken(authentication);
        jwtRepository.save(
                RefreshToken.builder()
                        .username(authentication.getName())
                        .token(jwtToken.getRefreshToken())
                        .build());
        return jwtToken;
    }

    @Transactional
    public MemberCreateResponseDto signUp(SignUpDto signUpDto) {
        if (memberRepository.existsByUsername(signUpDto.getUsername())) {
            throw new IllegalArgumentException("이미 사용 중인 사용자 이름입니다.");
        }
        String encodedPassword = passwordEncoder.encode(signUpDto.getPassword());
        List<String> roles = new ArrayList<>();
        roles.add("ADMIN");  // USER 권한 부여
        return MemberCreateResponseDto.from(memberRepository.save(signUpDto.from(encodedPassword, roles)));
    }
}