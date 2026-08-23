package com.husovic.securevault.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI secureVaultOpenApi() {
        return new OpenAPI().info(new Info()
                .title("SecureVault API")
                .version("0.0.1")
                .description("Hibridni kriptosistem sa empirijskom komparativnom analizom algoritama. "
                        + "Praktični dio završnog rada \"Enkripcijski algoritmi\".")
                .contact(new Contact().name("Hamza Husović"))
                .license(new License().name("Edukativna upotreba")));
    }
}
