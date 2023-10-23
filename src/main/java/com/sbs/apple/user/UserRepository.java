package com.sbs.apple.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
@Repository
public interface UserRepository extends JpaRepository<SiteUser, Integer> {
    Optional<SiteUser> findByusername(String username);

    boolean existsByUsername(String username);

    @Query(value = "SELECT * FROM site_user WHERE gender = :gender ORDER BY RAND() LIMIT :count", nativeQuery = true)
    List<SiteUser> findRandomUsersByGender(@Param("gender") String gender, @Param("count") int count);

}
