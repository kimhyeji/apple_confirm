package com.sbs.apple.base.app;

import lombok.Getter;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
@Configuration
public class AppConfig {
    @Getter
    public static String genFileDirPath;

    @Value("${custom.genFile.dirPath}")
    public void setFileDirPath(String genFileDirPath) {
        AppConfig.genFileDirPath = genFileDirPath;
    }
}
