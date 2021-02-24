package top.anets;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class OauthSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthSecurityApplication.class, args);
	}

}
