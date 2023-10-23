package com.sbs.apple.user;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserPasswordChangeForm {

    @NotEmpty(message = "비밀번호는 필수항목입니다.")
    private String password;

    @NotEmpty(message = "비밀번호는 필수항목입니다.")
    private String newPassword1;

    @NotEmpty(message = "비밀번호 확인은 필수항목입니다.")
    private String newPassword2;}
