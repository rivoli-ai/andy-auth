package com.example.andyauth;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OidcUser user, Model model) {
        if (user != null) {
            model.addAttribute("user", user);
            model.addAttribute("name", user.getFullName() != null ?
                user.getFullName() : user.getEmail());
        }
        return "home";
    }

    @GetMapping("/profile")
    @ResponseBody
    public Map<String, Object> profile(@AuthenticationPrincipal OidcUser user) {
        Map<String, Object> profile = new HashMap<>();
        profile.put("sub", user.getSubject());
        profile.put("name", user.getFullName());
        profile.put("email", user.getEmail());
        profile.put("claims", user.getClaims());
        return profile;
    }

    @GetMapping("/tokens")
    @ResponseBody
    public Map<String, Object> tokens(
            @RegisteredOAuth2AuthorizedClient("andy-auth") OAuth2AuthorizedClient client,
            @AuthenticationPrincipal OidcUser user
    ) {
        Map<String, Object> tokens = new HashMap<>();

        if (client.getAccessToken() != null) {
            String tokenValue = client.getAccessToken().getTokenValue();
            tokens.put("access_token", tokenValue.substring(0, Math.min(20, tokenValue.length())) + "...");
            tokens.put("expires_at", client.getAccessToken().getExpiresAt());
            tokens.put("scopes", client.getAccessToken().getScopes());
        }

        tokens.put("has_refresh_token", client.getRefreshToken() != null);
        tokens.put("has_id_token", user.getIdToken() != null);

        return tokens;
    }
}
