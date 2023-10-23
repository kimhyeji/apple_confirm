package com.sbs.apple;

import com.sbs.apple.chat.ChatRoom;
import com.sbs.apple.chat.ChatRoomService;
import com.sbs.apple.user.SiteUser;
import com.sbs.apple.user.UserService;
import com.sbs.apple.util.DataCreator;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class MainController {

    private final ChatRoomService chatRoomService;
    private final UserService userService;

    private final DataCreator dataCreator;
    @Value("${spring.jpa.hibernate.ddl-auto}")
    private String ddlAutoValue;

    // ************ TEST DATA CREATE ***************
    private boolean isTestDataCreated = false;
    // *********************************************

    @GetMapping("/")
    public String showMain(Model model, Principal principal) {
        System.out.println("메인페이지 실행1");
        // ************ TEST DATA CREATE ***************
        if (!isTestDataCreated && ddlAutoValue.equals("create")) {
            dataCreator.createTestData();
            isTestDataCreated = true;
        }// *********************************************


        ChatRoom chatRoom= chatRoomService.findLastRoom();

        if(principal==null){
            return "main";
        }

        SiteUser loginUser = userService.getUserbyName(principal.getName());

        if(loginUser==null) {
            return "main";
        }

        List<SiteUser> siteUsers2 = userService.getAllUser2(loginUser);

        List<SiteUser> siteUsers =userService.getUsersNotRoom(loginUser,siteUsers2);



        System.out.println("메인페이지 실행2");
        model.addAttribute("siteUsers", siteUsers);

        model.addAttribute("chatRoom", chatRoom);

        System.out.println("메인페이지 실행3");

        String username = principal.getName();
        SiteUser siteUser =userService.getUserbyName(username);
        String Gender =siteUser.getGender();
        List<SiteUser> userList = userService.getFourUsers(Gender); // 사용자 정보를 가져오는 예시 메서드
        model.addAttribute("userList", userList);

        return "main";
    }
}
