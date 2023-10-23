package com.sbs.apple.cybermoney;

import com.sbs.apple.user.SiteUser;
import com.sbs.apple.user.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class CyberMoneyServiceImpl implements CyberMoneyService {
    private final UserRepository userRepository;

    public CyberMoneyServiceImpl(UserRepository siteUserRepository) {
        this.userRepository = siteUserRepository;
    }

    @Override
    public void sendCyberMoney(SiteUser senderUser, SiteUser recipientUser, int amount) {
        // 보내는 사람이 충분한 사이버 머니를 가지고 있는지 확인합니다.
        if (senderUser.getCyberMoney() >= amount) {
            // 보내는 사람의 계좌에서 금액을 차감합니다.
            senderUser.setCyberMoney(senderUser.getCyberMoney() - amount);
            userRepository.save(senderUser);

            // 받는 사람의 계좌에 금액을 추가합니다.
            recipientUser.setReceivedCyberMoney(recipientUser.getReceivedCyberMoney() + amount);
            userRepository.save(recipientUser);
        } else {
            throw new IllegalArgumentException("사이버 머니가 부족합니다.");
        }
    }
}