package leeyeongjae.yryrserver.member.domain.dto;

import leeyeongjae.yryrserver.member.domain.Member;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class MemberCreateResponseDto {
    private Integer id;
    private String username;
    private String nickname;
    static public MemberCreateResponseDto from(Member member) {
        return MemberCreateResponseDto.builder()
                .id(member.getId())
                .username(member.getUsername())
                .nickname(member.getNickname())
                .build();
    }
}
