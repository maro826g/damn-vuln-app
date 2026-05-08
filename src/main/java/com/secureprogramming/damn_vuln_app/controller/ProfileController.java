package com.secureprogramming.damn_vuln_app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ProfileController {

    @GetMapping("/profile")
    public String profile(@RequestParam(defaultValue = "1") Long id, Model model) {

        // VULNERABLE: no check that the logged-in user owns this id
        // Normal users know about id=1 (themselves), but id=1337 is the
        // hidden admin profile they should NOT be able to access.

        if (id == 1) {
            model.addAttribute("profileId",    1);
            model.addAttribute("name",         "Alex Johnson");
            model.addAttribute("email",        "alex.johnson@talentbridge.com");
            model.addAttribute("department",   "Engineering");
            model.addAttribute("role",         "Junior Developer");
            model.addAttribute("salary",       "$72,000");
            model.addAttribute("isAdmin",      false);
            model.addAttribute("flag",         null);

        } else if (id == 1337) {
            // Hidden admin profile — this is what the attacker finds
            model.addAttribute("profileId",    1337);
            model.addAttribute("name",         "Sarah Mitchell");
            model.addAttribute("email",        "s.mitchell@talentbridge.com");
            model.addAttribute("department",   "Executive");
            model.addAttribute("role",         "Chief Information Officer");
            model.addAttribute("salary",       "$310,000");
            model.addAttribute("isAdmin",      true);
            model.addAttribute("flag",         "FLAG{IDOR_ACC3SS_1337_PR0FILE}");

        } else {
            // Any other id — show generic not found within the page
            model.addAttribute("profileId",    id);
            model.addAttribute("name",         null);
        }

        return "profile";
    }
}