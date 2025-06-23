package com.study.security.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI() {
        String jwtSchemeName = "bearerAuth";
        SecurityRequirement securityRequirement = new SecurityRequirement().addList(jwtSchemeName);

        Components components = new Components()
                .addSecuritySchemes(jwtSchemeName, new SecurityScheme()
                        .name(jwtSchemeName)
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("JWT 토큰을 입력하세요. (Bearer 접두사는 자동으로 추가됩니다)"));

        return new OpenAPI()
                .info(apiInfo())
                .addServersItem(new Server().url("/"))
                .addSecurityItem(securityRequirement)
                .components(components);
    }

    private Info apiInfo() {
        return new Info()
                .title("Spring Security Demo API")
                .description("Spring Security를 활용한 회원 관리 시스템 API 문서")
                .version("1.0.0")
                .contact(new Contact()
                        .name("Your Name")
                        .email("your-email@example.com")
                        .url("https://github.com/yourusername"))
                .license(new License()
                        .name("Apache 2.0")
                        .url("https://www.apache.org/licenses/LICENSE-2.0"));
    }
}