package com.sbs.apple.user;


import com.sbs.apple.Base;
import com.sbs.apple.chat.ChatRoom;
import com.sbs.apple.report.Report;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.Where;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static lombok.AccessLevel.PUBLIC;

@Getter
@Setter
@Entity
@AllArgsConstructor(access = PUBLIC)
@NoArgsConstructor(access = PUBLIC)
@SuperBuilder
@ToString(callSuper = true)
@Where(clause = "USER_STOP is FALSE")
public class SiteUser extends Base {
    private boolean userStop;
    private String filename;
    private String filepath;
    //회원가입 할 때 기본 정보
    @Column(unique = true)
    private String username;
    private String password;
    @Column(unique = true)
    private String nickname;
    private String gender; //성별
    //기본 프로필 기입
    private int age;//나이

    private String living;//사는 지역

    private String hobby;//취미 여려개 추가할 수 있게 변경하기

    private int tall; //키

    private String body_type; //체형

    @Column(nullable = true)
    private String smoking; //흡연 유무

    private String drinking; //음주 유무
    private String style; //스타일(성격)
    private String religion; //종교
    private String mbti; //MBTI
    private String school; //학력
    private String job; //직장
    private String About_Me; //자기소개

    private String desired_age; //원하는 나이 어떻게 구현할지 다시 고민
    private String desired_living; //원하는 지역
    private String desired_hobby; // 여러개 고를 수 있게 하기
    private String desired_tall; // 원하는 키 어떻게 범위 설정할지 다시 고민
    private String desired_body_type; //원하는 체형
    private String desired_smoking; // 원하는 흡연 유무
    private String desired_drinking; // 원하는 음주 유무
    private String desired_style; //원하는 스타일
    private String desired_religion; //원하는 종교
    private String desired_mbti; //원하는 MBTI



    @OneToMany(mappedBy = "siteUser" , cascade = CascadeType.REMOVE)
    private List<ChatRoom> chatRoomList;





    private String desired_school;
    private String desired_job;

    @OneToMany(mappedBy = "siteUser", cascade = CascadeType.REMOVE)
    private List<Report> reportList;

    @Column
    private int cyberMoney = 0; // 기본값 0으로 초기화

    @Column
    private Integer receivedCyberMoney = 0; // 다른 사용자로부터 받은 사이버머니 기본값 0으로 초기화
    public Integer getReceivedCyberMoney() {
        if (receivedCyberMoney == null) {
            return 0; // 또는 다른 기본값을 사용할 수 있습니다.
        }
        return receivedCyberMoney;
    }

    //여러개를 선택해야할 때의 칼럼
    public List<? extends GrantedAuthority> getGrantedAuthorities() {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority("siteuser"));
        grantedAuthorities.add(new SimpleGrantedAuthority("admin"));
        return grantedAuthorities;
    }

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<UserRole> authorities = new HashSet<>();

    public boolean hasRole(UserRole role) {
        return authorities.contains(role);
    }

    public boolean isAdmin() {
        return hasRole(UserRole.ADMIN);
    }

}