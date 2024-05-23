package leeyeongjae.server.member.domain.dto;

import lombok.Data;

@Data
public class MemberCreateRequestDto {
    private Integer id;
    private String username;
    private String nickname;
}
