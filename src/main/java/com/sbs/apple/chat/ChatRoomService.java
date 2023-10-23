package com.sbs.apple.chat;

import com.sbs.apple.user.SiteUser;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class ChatRoomService {
    private final ChatRoomRepository chatRoomRepository;


    public ChatRoom create(SiteUser user,SiteUser user2){
        ChatRoom chatRoom = new ChatRoom();
//        chatRoom.setUserId1(user);
//        chatRoom.setUserId2(userId2);
        chatRoom.setCreateDate(LocalDateTime.now());
        chatRoom.setSiteUser(user);
        chatRoom.setSiteUser2(user2);
        chatRoomRepository.save(chatRoom);
        return chatRoom;

    }

    public Integer findLastId(){
        return chatRoomRepository.findMaxId();

    }

    public ChatRoom findLastRoom(){


        if(chatRoomRepository.findTopByOrderByIdDesc().isEmpty()){
            return null;
        }

        return chatRoomRepository.findTopByOrderByIdDesc().get();
    }

    public List<ChatRoom> findAll(){
        return chatRoomRepository.findAll();
    }

    public List<ChatRoom> findByUser(SiteUser user){
       return chatRoomRepository.findChatRoomsByUserId(user);
    }


    public ChatRoom findRoomByUserIdAndUserId2(Integer userId, Integer userId2) {
        return chatRoomRepository.findRoomByUserIdAndUserId2(userId, userId2);

    }

    public List<ChatRoom> getAll() {
        if( chatRoomRepository.findAll()==null){
            return null;
        }
        return  chatRoomRepository.findAll();
    }

    public ChatRoom findById(Integer roomId) {
        Optional<ChatRoom> room= chatRoomRepository.findById(roomId);
         if(room.isEmpty()){
             System.out.println("지울 방이 없습니다.");
             return null;
         }
         ChatRoom room2=room.get();
         return room2;
    }


    public void delete(ChatRoom chatRoom) {
        this.chatRoomRepository.delete(chatRoom);
    }
}
