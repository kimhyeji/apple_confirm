package com.sbs.apple.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Service
public class UserSecurityService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<SiteUser> _siteUser = this.userRepository.findByusername(username);
        SiteUser user = this.userRepository.findByUsername(username);

        if (_siteUser.isEmpty()) {
            throw new UsernameNotFoundException("사용자를 찾을수 없습니다.");
        }

        if (isBannedUser(user)) {
            throw new UsernameNotFoundException("영구정지 된 계정입니다.");
        }

        SiteUser siteUser = _siteUser.get();
        List<GrantedAuthority> authorities = siteUser.getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getValue()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority(UserRole.USER.getValue()));
        return new User(siteUser.getUsername(), siteUser.getPassword(), authorities);
    }

    private boolean isBannedUser(SiteUser user) {
        return user.isUserStop();
    }
}