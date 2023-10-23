package com.sbs.apple.chat;

import com.sbs.apple.user.SiteUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ChatRoomRepository extends JpaRepository<ChatRoom, Integer> {

    @Query(value = "SELECT MAX(id) FROM your_entity", nativeQuery = true)
    Integer findMaxId();

    Optional<ChatRoom> findTopByOrderByIdDesc();

    @Query("SELECT cr FROM ChatRoom cr WHERE cr.siteUser = :user OR cr.siteUser2 = :user")
    List<ChatRoom> findChatRoomsByUserId(@Param("user") SiteUser user);



    @Query("SELECT cr FROM ChatRoom cr WHERE cr.siteUser.id = :userId AND cr.siteUser2.id = :userId2")
    ChatRoom findRoomByUserIdAndUserId2(@Param("userId") Integer userId,@Param("userId2") Integer userId2);






}
