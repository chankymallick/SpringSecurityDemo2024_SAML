    /*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.quest.questdemo.config.AppConfig;

/**
 *
 * @author MMallick
 */
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

public class SecurityWebApplicationInitializer extends AbstractSecurityWebApplicationInitializer {
    // This class will ensure the springSecurityFilterChain is registered for every URL in your application.

    @Override
    protected boolean enableHttpSessionEventPublisher() {
        return true;
    }

}
