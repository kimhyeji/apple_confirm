package com.sbs.apple;

import com.sbs.apple.user.SiteUser;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Setter
@Getter
public class Hobby {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(length =200)
    private String name;

    @ManyToOne
    @JoinColumn(name = "person_id")
    private SiteUser user;
}
