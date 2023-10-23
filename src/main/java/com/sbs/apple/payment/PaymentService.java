package com.sbs.apple.payment;

import com.sbs.apple.user.SiteUser;
import com.sbs.apple.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class PaymentService {

    @Autowired
    private UserRepository userRepository;

    public void grantCyberMoneyToUser(String username, int amount) {
        Optional<SiteUser> optionalUser = userRepository.findByusername(username);

        if (optionalUser.isPresent()) {
            SiteUser user = optionalUser.get();
            int currentCyberMoney = user.getCyberMoney();
            int newCyberMoney = currentCyberMoney + amount;
            user.setCyberMoney(newCyberMoney);

            // 변경된 정보를 데이터베이스에 저장
            userRepository.save(user);
        }
    }
}