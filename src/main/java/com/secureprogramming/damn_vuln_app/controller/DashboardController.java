package com.secureprogramming.damn_vuln_app.controller;

import jakarta.persistence.EntityManager;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Controller
public class DashboardController {

    @Autowired
    private EntityManager entityManager;

    // ─── MAIN DASHBOARD ─────────────────────────────────────────
    @GetMapping("/")
    public String dashboard(
            @RequestParam(required = false) String jobApplication,
            @CookieValue(value = "admin_access", defaultValue = "false") String adminAccess,
            HttpServletResponse response,
            Model model) {

        // BAC cookie — set to false by default
        if (!"true".equals(adminAccess)) {
            Cookie adminCookie = new Cookie("admin_access", "false");
            adminCookie.setPath("/");
            response.addCookie(adminCookie);
        }

        // XSS flag cookie — always set so alert(document.cookie) reveals it
        Cookie flagCookie = new Cookie("FLAG", "FLAG{XSS_C00K13_H34ST}");
        flagCookie.setPath("/");
        response.addCookie(flagCookie);

        // XSS — job application title reflected unescaped
        if (jobApplication != null && !jobApplication.isEmpty()) {
            model.addAttribute("jobApplication", jobApplication);
        }

        return "dashboard";
    }

    // ─── SQLi — JOB SEARCH ──────────────────────────────────────
    @GetMapping("/jobs/search")
    public String jobSearch(
            @RequestParam(required = false) String title,
            Model model) {

        if (title != null && !title.isEmpty()) {

            // VULNERABLE: The application tries to only show 'public' jobs
            String query = "SELECT * FROM job_positions WHERE status = 'public' AND title = '" + title + "'";

            try {
                List results = entityManager
                        .createNativeQuery(query,
                                com.secureprogramming.damn_vuln_app.model.JobPosition.class)
                        .getResultList();
                model.addAttribute("jobResults", results);
            } catch (Exception e) {
                model.addAttribute("sqlError", "Database error: " + e.getMessage());
            }
        }
        return "dashboard";
    }

    // ─── SSRF — LINKEDIN PROFILE IMPORTER ───────────────────────
    @PostMapping("/import-profile")
    public String importProfile(
            @RequestParam String profileUrl,
            Model model) {
        try {
            // VULNERABLE: no URL validation
            RestTemplate restTemplate = new RestTemplate();
            String result = restTemplate.getForObject(profileUrl, String.class);
            model.addAttribute("importedData", result);
        } catch (Exception e) {
            model.addAttribute("importedData", "Failed to fetch: " + e.getMessage());
        }
        return "dashboard";
    }
    // ─── INTERNAL API (Target for SSRF) ─────────────────────────
    @GetMapping("/internal")
    @ResponseBody // Returns raw text, not a Thymeleaf template
    public String internalMetrics(jakarta.servlet.http.HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();

        // Check if the request is coming from localhost (IPv4 or IPv6)
        if ("127.0.0.1".equals(remoteAddr) || "0:0:0:0:0:0:0:1".equals(remoteAddr)) {
            return "SUCCESS: Internal System Metrics Accessed.\n" +
                    "CPU: 12%\n" +
                    "RAM: 45%\n" +
                    "FLAG{SSRF_P1V0T_M4ST3R}";
        } else {
            // Block external users
            return "HTTP 403 Forbidden: This endpoint is restricted to internal network (localhost) only. Your IP is: " + remoteAddr;
        }
    }

    // ─── BAC — ADMIN PANEL ──────────────────────────────────────
    @GetMapping("/admin")
    public String adminPage(
            @CookieValue(value = "admin_access", defaultValue = "false") String adminAccess,
            Model model) {
        if ("true".equals(adminAccess)) {
            return "admin";
        }
        model.addAttribute("error", "ACCESS DENIED: You do not have admin privileges.");
        return "dashboard";
    }
}