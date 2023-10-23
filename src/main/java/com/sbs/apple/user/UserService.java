package com.sbs.apple.user;

import com.sbs.apple.DataNotFoundException;
import com.sbs.apple.chat.ChatRoom;
import com.sbs.apple.chat.ChatRoomService;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.util.*;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ChatRoomService chatRoomService;
    private  UserService userService;

    public SiteUser getUser(Integer id) {
        Optional<SiteUser> user = this.userRepository.findById(id);
        if (user.isPresent()) {
            return user.get();
        } else {
            throw new DataNotFoundException("user not found");
        }
    }

    public SiteUser getUserbyName(String name) {
        Optional<SiteUser> user = this.userRepository.findByusername(name);
        if (user.isPresent()) {
            return user.get();
        } else {

            return null;
        }
    }

    public SiteUser create(boolean userStop, MultipartFile file, String username, String password, String nickname, String gender)
            throws Exception {
        SiteUser user = new SiteUser();
        user.setUserStop(userStop);
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setNickname(nickname);
        user.setGender(gender);
         String projectPath = System.getProperty("user.dir")+"\\src\\main\\resources\\static\\files";
         UUID uuid = UUID.randomUUID();
         String fileName =uuid + "_" + file.getOriginalFilename();
         File saveFile =new File(projectPath,fileName);
         file.transferTo(saveFile);
         user.setFilename(fileName);
        user.setFilepath("/files/"+fileName);

        this.userRepository.save(user);
        return user;
    }

    public SiteUser create( String username, String password, String nickname, String gender) {
        SiteUser user = new SiteUser();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setNickname(nickname);
        user.setGender(gender);
        this.userRepository.save(user);
        return user;
    }

    public SiteUser add_profile(SiteUser user, int age, String living, String hobby, int tall, String bodyType,
                                String smoking, String drinking, String style, String religion,
                                String mbti, String school, String job, String About_Me) {
        user.setAge(age);
        user.setLiving(living);
        user.setHobby(hobby);
        user.setTall(tall);
        user.setBody_type(bodyType);
        user.setSmoking(smoking);
        user.setDrinking(drinking);
        user.setStyle(style);
        user.setReligion(religion);
        user.setMbti(mbti);
        user.setSchool(school);
        user.setJob(job);
        user.setAbout_Me(About_Me);
        this.userRepository.save(user);
        return user;
    }


    public SiteUser add_desired(SiteUser user, String desiredAge, String desiredLiving, String desiredHobby,
                                String desiredTall, String desiredBodyType, String desiredSmoking,
                                String desiredDrinking, String desiredStyle, String desiredReligion,
                                String desiredMbti, String desiredSchool, String desiredJob) {
        user.setDesired_age(desiredAge);
        user.setDesired_living(desiredLiving);
        user.setDesired_hobby(desiredHobby);
        user.setDesired_tall(desiredTall);
        user.setDesired_body_type(desiredBodyType);
        user.setDesired_smoking(desiredSmoking);
        user.setDesired_drinking(desiredDrinking);
        user.setDesired_style(desiredStyle);
        user.setDesired_religion(desiredReligion);
        user.setDesired_mbti(desiredMbti);
        user.setDesired_school(desiredSchool);
        user.setDesired_job(desiredJob);
        this.userRepository.save(user);
        return user;
    }

    public boolean isCorrectPassword(String username, String password) {
        SiteUser user = getUserbyName(username);
        String actualPassword = user.getPassword();
        return passwordEncoder.matches(password, actualPassword);
    }

    public void updatePassword(String username, String newPassword) {
        SiteUser user = getUserbyName(username);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public void delete(SiteUser siteUser) {
        // 해당 사용자와 연결된 answer 레코드 삭제
//        List<Answer> userAnswers = answerRepository.findByAuthor(siteUser);
//        answerRepository.deleteAll(userAnswers);

        // 해당 사용자와 연결된 question 레코드 삭제
//        List<Question> userQuestions = questionRepository.findByAuthor(siteUser);
//        questionRepository.deleteAll(userQuestions);

        // 사용자 삭제
        this.userRepository.delete(siteUser);
    }

    //소셜 로그인
    @Transactional
    public SiteUser whenSocialLogin(String providerTypeCode, String username, String nickname) {
        // 소셜 로그인를 통한 가입시 비번은 없다.
        return create(username, "", nickname, ""); // 최초 로그인 시 딱 한번 실행
    }


    public List<SiteUser> getAllUser() {
        List<SiteUser> siteUsers = userRepository.findAll();
        return siteUsers;
    }

    public List<SiteUser> getFourUsers(String gender) {
        List<SiteUser> randomUsers;

        if ("남".equals(gender)) {
            randomUsers = this.userRepository.findRandomUsersByGender("여", 4);
        } else if ("여".equals(gender)) {
            randomUsers = this.userRepository.findRandomUsersByGender("남", 4);
        } else {
            // Handle invalid gender or other cases
            randomUsers = Collections.emptyList();
        }

        return randomUsers;
    }

    public void grantAdminAuthority(String username) {
        SiteUser user = userRepository.findByusername(username).orElse(null);

        if (user != null) {
            // 기존 권한 수정
            user.getAuthorities().clear(); // 모든 권한 제거
            user.getAuthorities().add(UserRole.ADMIN); // "ADMIN" 권한 추가
            userRepository.save(user);
        }
    }
    //관리자 권한 삭제
    public void deleteAdminAuthority(String username) {
        SiteUser user = userRepository.findByusername(username).orElse(null);

        if (user != null) {
            // 기존 권한 수정
            user.getAuthorities().clear(); // 모든 권한 제거
            userRepository.save(user);
        }
    }

    //로그인 한 유저 제외한 유저 목록들 불러오기
    public List<SiteUser> getAllUser2(SiteUser loginUser) {
        List<SiteUser> siteUsers = userRepository.findAll();

        for (int i = 0; i < siteUsers.size(); i++) {
            if (siteUsers.get(i).getId() == loginUser.getId()) {
                siteUsers.remove(i);
            }
        }
        return siteUsers;
    }


    //로그인한 사용자와 채팅방이 없는 유저만 불러오는 함수
    public List<SiteUser> getUsersNotRoom(SiteUser loginUser, List<SiteUser> siteUsers) {
        List<ChatRoom> AllRooms = chatRoomService.getAll();



        //이미 채팅방이 있는 유저들 id 저장소
        List<Integer> chatUsers = new ArrayList<>();

        for (int i = 0; i < AllRooms.size(); i++) {
            if (AllRooms.get(i).getSiteUser().getId() == loginUser.getId()) {
                chatUsers.add(AllRooms.get(i).getSiteUser2().getId()); //내가 초대한 유저의 아이디 저장
            }

            if (AllRooms.get(i).getSiteUser2().getId() == loginUser.getId()) {
                chatUsers.add(AllRooms.get(i).getSiteUser().getId()); //나를 초대한 유저의 아이디 저장
            }
        }

        //채팅방이 이미 있어서 삭제해야할  유저들이 있어야되는 chatUsers 에서의 인덱스값 들
        List<Integer> deleteUserIds = new ArrayList<>();
        System.out.println(chatUsers.toString());

        //그 인덱스 값들에 있는 user 들 삭제해서 중복된 채팅방 못만들게 하기
        for (int i = 0; i < siteUsers.size(); i++) {
            for (int j = 0; j < chatUsers.size(); j++) {
                if (siteUsers.get(i).getId() == chatUsers.get(j)) {
                    deleteUserIds.add(i);

                }
            }


        }


        for (int i = deleteUserIds.size() - 1; i >= 0; i--) {
            siteUsers.remove((int) deleteUserIds.get(i));
        }
        return siteUsers;

    }

    public void changeUserStop(SiteUser siteUser) {
        siteUser.setUserStop(true);
        userRepository.save(siteUser);
    }
    @Scheduled(fixedDelay = 60 * 1000) // 1분(밀리초) 후에 실행
    public void resetUserStop(SiteUser siteUser) {
        siteUser.setUserStop(false);
        userRepository.save(siteUser);
    }
}


