package leeyeongjae.yryrserver.member.domain.dto;

import leeyeongjae.yryrserver.member.domain.Member;
import lombok.Builder;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
public class SignUpDto {

    private String username;
    private String password;
    private String nickname;
    private List<String> roles = new ArrayList<>();

    public Member from(String encodedPassword, List<String> roles) {
        return Member.builder()
                .username(username)
                .password(encodedPassword)
                .nickname(nickname)
                .roles(roles)
                .build();
    }
}
