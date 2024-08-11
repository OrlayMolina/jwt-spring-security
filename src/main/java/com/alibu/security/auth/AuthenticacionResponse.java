package com.alibu.security.auth;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticacionResponse {

    private String token;
}
