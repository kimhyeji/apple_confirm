package com.sbs.apple.admin;

import com.sbs.apple.report.Report;
import com.sbs.apple.report.ReportService;
import com.sbs.apple.user.SiteUser;
import com.sbs.apple.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@RequiredArgsConstructor
@Controller
@RequestMapping("/admin")
public class AdminController {
    private final UserService userService;
    private final AdminAccountService adminAccountService;
    private final ReportService reportService;


    @GetMapping("/report_list")
    public String report_list(Model model){
        List<Report> reportList = this.reportService.getList();
        model.addAttribute("reportList",reportList);
        return "report_list";
    }

    @GetMapping("/punish/{id}")
    public String punish(Model model, @PathVariable("id") Integer id){
        model.addAttribute("id",id);
        return "punish";
    }
    @GetMapping("/Permanent_stop/{id}")
    public String Permanent_stop(@PathVariable Integer id){
        SiteUser siteUser = this.userService.getUser(id);
        userService.changeUserStop(siteUser);
        userService.resetUserStop(siteUser);
        return "main";
    }



}
