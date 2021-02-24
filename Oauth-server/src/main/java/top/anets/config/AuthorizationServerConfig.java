/**
 * 
 */
package top.anets.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import top.anets.jwt.JwtTokenEnhancer;
import top.anets.service.UserService;

/**
 * 认证服务器配置   |  配置认证服务对象（处理通过客户端认证 的用户的登录）  和  客户端服务对象（处理用户 在 客户端的认证）
 * Created by macro on 2019/9/30.
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;
    @Autowired
    @Qualifier("jwtTokenStore")
    private TokenStore tokenStore; 
    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter; 
    @Autowired
    private JwtTokenEnhancer jwtTokenEnhancer;
    /**
     * 认证服务器配置  --- 需要配置认证管理器对象和 userDetailsService对象, 
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
//    	 jwt增强代码
    	 TokenEnhancerChain enhancerChain = new TokenEnhancerChain();
         List<TokenEnhancer> delegates = new ArrayList<>();
         delegates.add(jwtTokenEnhancer); //配置JWT的内容增强器
         delegates.add(jwtAccessTokenConverter);
         enhancerChain.setTokenEnhancers(delegates);
         
         
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userService)
                .tokenStore(tokenStore) //配置令牌存储策略
                .accessTokenConverter(jwtAccessTokenConverter) //解密令牌需要的签名转换
                .tokenEnhancer(enhancerChain); //jwt增强
    }

    
    /**
     * 客户端配置---需要配置客户端id和秘钥 
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("admin")//配置client_id
                .secret(passwordEncoder.encode("admin123456"))//配置client_secret
                .accessTokenValiditySeconds(3600)//配置访问token的有效期
                .refreshTokenValiditySeconds(864000)//配置刷新token的有效期
//                .redirectUris("http://www.baidu.com")//配置redirect_uri，用于授权成功后跳转
//                .redirectUris("http://localhost:9501/login") //单点登录时配置
//                .autoApprove(true) //自动授权配置
                .scopes("all")//配置申请的权限范围
                .authorizedGrantTypes("authorization_code","password","client_credentials","implicit","refresh_token");//配置grant_type，表示授权类型,刷新令牌
    }
    
    
    
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security.tokenKeyAccess("isAuthenticated()"); // 获取密钥需要身份认证，使用单点登录时必须配置
    }
    
    
    
    
}