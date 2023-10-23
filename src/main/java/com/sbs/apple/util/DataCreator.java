
package com.sbs.apple.util;


import com.sbs.apple.user.SiteUser;
import com.sbs.apple.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Random;


@Component
public class DataCreator {
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    UserRepository userRepository;

    // 생성되는 유저 개수
    protected Integer userNum = 20;

    Random random = new Random();

    public void createTestData(){
        createUser();
    }


    public void createUser() {
        for(int i = 0; i < userNum; i++){
            char asciiChar = (char) (i + 65);
            String username = String.valueOf(asciiChar);

            SiteUser user = new SiteUser();
            user.setUserStop(false);
            user.setUsername(username);
            user.setPassword(passwordEncoder.encode(username));
            user.setNickname("유저 " + username);
            user.setGender("남");
            user.setAge(random.nextInt(30));
            user.setLiving("서울");
            user.setHobby("골프");
            user.setTall(random.nextInt(170));
            user.setBody_type("평범한");
            user.setSmoking("비흡연");
            user.setDrinking("가끔");
            user.setStyle("슬림한");
            user.setReligion("무교");
            user.setMbti("INFP");
            user.setSchool("4년제 졸업");
            user.setJob("무직");
            user.setAbout_Me("반갑소");
            user.setDesired_age("상관없음");
            user.setDesired_living("서울");
            user.setDesired_hobby("골프");
            user.setDesired_tall("상관없음");
            user.setDesired_body_type("평범한");
            user.setDesired_smoking("비흡연");
            user.setDesired_drinking("가끔");
            user.setDesired_style("슬림한");
            user.setDesired_religion("무교");
            user.setDesired_mbti("INFP");
            user.setDesired_school("4년제 졸업");
            user.setDesired_job("무직");
            userRepository.save(user);
            System.out.println("qwe");
        }

        for(int i = 0; i < userNum; i++){
            char asciiChar = (char) (i + 97);
            String username = String.valueOf(asciiChar);

            SiteUser user = new SiteUser();
            user.setUserStop(false);
            user.setUsername(username);
            user.setPassword(passwordEncoder.encode(username));
            user.setNickname("유저 " + username);
            user.setGender("여");
            user.setAge(random.nextInt(30));
            user.setLiving("서울");
            user.setHobby("골프");
            user.setTall(random.nextInt(170));
            user.setBody_type("평범한");
            user.setSmoking("비흡연");
            user.setDrinking("가끔");
            user.setStyle("슬림한");
            user.setReligion("무교");
            user.setMbti("INFP");
            user.setSchool("4년제 졸업");
            user.setJob("무직");
            user.setAbout_Me("반갑소");
            user.setDesired_age("상관없음");
            user.setDesired_living("서울");
            user.setDesired_hobby("골프");
            user.setDesired_tall("상관없음");
            user.setDesired_body_type("평범한");
            user.setDesired_smoking("비흡연");
            user.setDesired_drinking("가끔");
            user.setDesired_style("슬림한");
            user.setDesired_religion("무교");
            user.setDesired_mbti("INFP");
            user.setDesired_school("4년제 졸업");
            user.setDesired_job("무직");
            userRepository.save(user);
        }
    }
}
