package com.quest.questdemo.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

@Controller
public class MvcController {

//    @Autowired
//    private UserDetailsService userDetailsService;      

//    @GetMapping("/profile")
//    public String profile(Model model, @AuthenticationPrincipal OidcUser oidcUser) {
//        model.addAttribute("profile", oidcUser.getClaims());
//        return "profile";
//    }

    @GetMapping("/LoginPage")
    public String login() {        
        return "LoginPage";
    }

    @GetMapping("/home")
    public String home(Model model, Authentication authentication) {
        String username = authentication.getName();  // Username from JDBC login 
        model.addAttribute("username", username);
        model.addAttribute("authorities", authentication.getAuthorities());        
        model.addAttribute("authtype", authentication.getDetails().toString().equals("DB") ? "DB":"LDAP");        
        return "home";
    }
}
