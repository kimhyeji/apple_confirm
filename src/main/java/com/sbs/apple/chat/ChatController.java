package com.sbs.apple.chat;

import com.sbs.apple.user.SiteUser;
import com.sbs.apple.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@Controller
@Slf4j
@RequestMapping("/chat")
@RequiredArgsConstructor
public class ChatController {
    private final SseEmitters sseEmitters;
    private final UserService userService;
    private final ChatMessages chatMessages;
    private final ChatRoomService chatRoomService;


    public record WriteMessageRequest(String authorName, String content) {
    }

    public record WriteMessageResponse(long id) {
    }


    //채팅방 만들기
    @PostMapping("/{roomId}/room")
    public String showRoom(  @RequestParam("userId") Integer userId2 , @PathVariable Long roomId, Model model, Principal principal) {
        System.out.println("채팅방 만들기 실행됨");

        SiteUser user =userService.getUserbyName(principal.getName());
        SiteUser user2= userService.getUser(userId2);



           ChatRoom room= chatRoomService.create(user, user2);
        model.addAttribute("roomId", room.getId());
        model.addAttribute("user",user);
        return "redirect:/chat/"+room.getId()+"/room3?userId2="+userId2;
    }

//   내가 초대했던 원래 있던 채팅방 들어가기
    @GetMapping("/{roomId}/room3")
    public String showRoom2(  @RequestParam("userId2") Integer userId2 ,Model model, Principal principal) {
        System.out.println("원래 있던 채팅방에 접속");
        SiteUser user =userService.getUserbyName(principal.getName());
        ChatRoom room = chatRoomService.findRoomByUserIdAndUserId2(user.getId(),userId2);
        System.out.println("채팅방에 들어갈 방번호 "+room.getId());

        model.addAttribute("roomId",room.getId() );
        model.addAttribute("user",user);
        return "chat/room";
    }

// 내가 초대 받은 채팅방 들어가기
    @GetMapping("/{roomId}/room2")
    public String showRoom3(  @RequestParam("userId") Integer userId ,Model model, Principal principal) {
        System.out.println("원래 있던 채팅방에 접속");
        SiteUser user =userService.getUserbyName(principal.getName());
        ChatRoom room = chatRoomService.findRoomByUserIdAndUserId2(userId,user.getId());
        System.out.println("채팅방에 들어갈 방번호 "+room.getId());

        model.addAttribute("roomId",room.getId() );
        model.addAttribute("user",user);

        return "chat/room";
    }

    @PostMapping("/{roomId}/writeMessage")
    @ResponseBody
    public RsData<WriteMessageResponse> writeMessage(@PathVariable Long roomId, @RequestBody WriteMessageRequest req) {

        ChatMessage message = new ChatMessage(req.authorName(), req.content());

        chatMessages.add(roomId, message);

        String groupKey = "chatRoom__" + roomId;
        sseEmitters.noti(groupKey, "chat__messageAdded");

        return new RsData<>(
                "S-1",
                "메세지가 작성되었습니다.",
                new WriteMessageResponse(message.getId())
        );
    }

    public record MessagesRequest(Long fromId) {
    }

    public record MessagesResponse(List<ChatMessage> messages, long count) {
    }

    @GetMapping("/{roomId}/messages")
    @ResponseBody
    public RsData<MessagesResponse> messages(@PathVariable Long roomId, MessagesRequest req) {
        List<ChatMessage> messages = chatMessages.from(roomId, req.fromId);

        return new RsData<>(
                "S-1",
                "성공",
                new MessagesResponse(messages, messages.size())
        );
    }

    @GetMapping("/allRoom")
    public String allRoom(Model model,Principal principal){
        SiteUser siteUser = userService.getUserbyName(principal.getName());
        List<ChatRoom> chatRooms=chatRoomService.findByUser(siteUser);
        List<ChatRoom> chatRooms2 =new ArrayList<>();
        List<ChatRoom> chatRooms3=new ArrayList<>() ;
        for(int i=0; i<chatRooms.size(); i++){
            if(chatRooms.get(i).getSiteUser().getId() == siteUser.getId()){
                chatRooms2.add(chatRooms.get(i));
            }else {
                chatRooms3.add(chatRooms.get(i));
            }
        }


        if( chatRooms2 !=null) {
            model.addAttribute("chatRoom2",chatRooms2); //내가 초대 한  채팅방
        }
        if( chatRooms3 !=null) {
            model.addAttribute("chatRoom3",chatRooms3);  //내가 초대 받은 채팅방
        }

        return "chat/allRoom";
    }


    @GetMapping("/{roomId}/delete")
    public String deleteRoom ( @PathVariable Integer roomId) {
        ChatRoom room=chatRoomService.findById(roomId);

        chatRoomService.delete(room);
        return "redirect:/chat/allRoom";


    }
}
