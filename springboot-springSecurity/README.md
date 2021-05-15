#              [Spring Security 案例实现和执行流程剖析](https://www.cnblogs.com/xifengxiaoma/p/10020960.html)

## Spring Security

Spring Security 是 Spring 社区的一个顶级项目，也是 Spring Boot 官方推荐使用的安全框架。除了常规的认证（Authentication）和授权（Authorization）之外，Spring Security还提供了诸如ACLs，LDAP，JAAS，CAS等高级特性以满足复杂场景下的安全需求。

Spring Security 应用级别的安全主要包含两个主要部分，即登录认证（Authentication）和访问授权（Authorization），首先用户登录的时候传入登录信息，登录验证器完成登录认证并将登录认证好的信息存储到请求上下文，然后在进行其他操作，如接口访问、方法调用时，权限认证器从上下文中获取登录认证信息，然后根据认证信息获取权限信息，通过权限信息和特定的授权策略决定是否授权。

接下来，本教程将分别对登录认证和访问授权的执行流程进行剖析，并在最后给出完整的案例实现，如果觉得先读前面原理比较难懂，可以先学习后面的实现案例，再结合案例理解登录认证和访问授权的执行原理。

## 登录认证

### 登录认证过滤器

如果在继承 WebSecurityConfigurerAdapter 的配置类中的 configure(HttpSecurity http) 方法中有配置 HttpSecurity 的 formLogin，则会返回一个 FormLoginConfigurer 对象。如下是一个 Spring Security 的配置样例， formLogin().x.x 就是配置使用内置的登录验证过滤器，默认实现为 UsernamePasswordAuthenticationFilter。

WebSecurityConfig.java


```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
    
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 使用自定义身份验证组件
        auth.authenticationProvider(new JwtAuthenticationProvider(userDetailsService));
    }
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.cors().and().csrf().disable()
            .authorizeRequests()
        // 首页和登录页面
        .antMatchers("/").permitAll()
        // 其他所有请求需要身份认证
        .anyRequest().authenticated()
        // 配置登录认证
        .and().formLogin().loginProcessingUrl("/login");
    }
}
```


查看 HttpSecurity , formLogion 方法返回一个 FormLoginConfigurer 对象。

HttpSecurity.java

```java
    public FormLoginConfigurer<HttpSecurity> formLogin() throws Exception {
        return getOrApply(new FormLoginConfigurer<>());
    }
```

而 FormLoginConfigurer 的构造函数内绑定了一个 UsernamePasswordAuthenticationFilter 过滤器。

FormLoginConfigurer.java

```java
    public FormLoginConfigurer() {
        super(new UsernamePasswordAuthenticationFilter(), null);
        usernameParameter("username");
        passwordParameter("password");
    }
```

再看 UsernamePasswordAuthenticationFilter 过滤器的构造函数内绑定了 POST 类型的 /login 请求，也就是说，如果配置了 formLogin 的相关信息，那么在使用 POST 类型的 /login URL进行登录的时候就会被这个过滤器拦截，并进行登录验证，登录验证过程我们下面继续分析。

UsernamePasswordAuthenticationFilter.java

```java
    public UsernamePasswordAuthenticationFilter() {
        super(new AntPathRequestMatcher("/login", "POST"));
    }
```

查看 UsernamePasswordAuthenticationFilter，发现它继承了 AbstractAuthenticationProcessingFilter，AbstractAuthenticationProcessingFilter 中的 doFilter 包含了触发登录认证执行流程的相关逻辑。

AbstractAuthenticationProcessingFilter.java


```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {

        ...

        Authentication authResult;
        try {
            authResult = attemptAuthentication(request, response);
            if (authResult == null) {
                // return immediately as subclass has indicated that it hasn't completed
                // authentication
                return;
            }
            sessionStrategy.onAuthentication(authResult, request, response);
        }

　　　　　...

        successfulAuthentication(request, response, chain, authResult);
    }
```


上面的登录逻辑主要步骤有两个：

\1. attemptAuthentication(request, response)

这是 AbstractAuthenticationProcessingFilter  中的一个抽象方法，包含登录主逻辑，由其子类实现具体的登录验证，如 UsernamePasswordAuthenticationFilter 是使用表单方式登录的具体实现。如果是非表单登录的方式，如JNDI等其他方式登录的可以通过继承 AbstractAuthenticationProcessingFilter 自定义登录实现。UsernamePasswordAuthenticationFilter 的登录实现逻辑如下。

UsernamePasswordAuthenticationFilter.java


```java
public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
　　　　　// 获取用户名和密码
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        username = username.trim();

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }
```


\2. successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)

登录成功之后，将认证后的 Authentication 对象存储到请求线程上下文，这样在授权阶段就可以获取到 Authentication 认证信息，并利用 Authentication 内的权限信息进行访问控制判断。

AbstractAuthenticationProcessingFilter.java


```java
    protected void successfulAuthentication(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {

        if (logger.isDebugEnabled()) {
            logger.debug("Authentication success. Updating SecurityContextHolder to contain: " + authResult);
        }
　　　　　// 登录成功之后，把认证后的 Authentication 对象存储到请求线程上下文，这样在授权阶段就可以获取到此认证信息进行访问控制判断
        SecurityContextHolder.getContext().setAuthentication(authResult);

        rememberMeServices.loginSuccess(request, response, authResult);

        // Fire event
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
                    authResult, this.getClass()));
        }

        successHandler.onAuthenticationSuccess(request, response, authResult);
    }
```


从上面的登录逻辑我们可以看到，Spring Security的登录认证过程是委托给 AuthenticationManager 完成的，它先是解析出用户名和密码，然后把用户名和密码封装到一个UsernamePasswordAuthenticationToken 中，传递给 AuthenticationManager，交由 AuthenticationManager 完成实际的登录认证过程。 

AuthenticationManager.java

```java
package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
\* Processes an {@link Authentication} request.
\* @author Ben Alex
*/
public interface AuthenticationManager {

　　Authentication authenticate(Authentication authentication) throws AuthenticationException;
}
```


AuthenticationManager 提供了一个默认的 实现 ProviderManager，而 ProviderManager 又将验证委托给了 AuthenticationProvider。

ProviderManager.java


```java
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
　　　　　...
　　 for (AuthenticationProvider provider : getProviders()) {
            if (!provider.supports(toTest)) {
                continue;
            }try {
                result = provider.authenticate(authentication);
                if (result != null) {
                    copyDetails(authentication, result);
                    break;
                }
            }
　　　　 ...

    }
```


根据验证方式的多样化，AuthenticationProvider 衍生出多种类型的实现，AbstractUserDetailsAuthenticationProvider 是 AuthenticationProvider 的抽象实现，定义了较为统一的验证逻辑，各种验证方式可以选择直接继承 AbstractUserDetailsAuthenticationProvider 完成登录认证，如 DaoAuthenticationProvider 就是继承了此抽象类，完成了从DAO方式获取验证需要的用户信息的。

AbstractUserDetailsAuthenticationProvider.java


```java
public Authentication authenticate(Authentication authentication) throws AuthenticationException {// Determine username
        String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
        boolean cacheWasUsed = true;
        UserDetails user = this.userCache.getUserFromCache(username);
        if (user == null) {
            cacheWasUsed = false;
            try {
　　　　　　　　　 // 子类根据自身情况从指定的地方加载认证需要的用户信息
                user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
            }
            ...try {
　　　　　　　// 前置检查，一般是检查账号状态，如是否锁定之类
            preAuthenticationChecks.check(user);

　　　　　　　// 进行一般逻辑认证，如 DaoAuthenticationProvider 实现中的密码验证就是在这里完成的
            additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
        }
        ...

　　　　 //　后置检查，如可以检查密码是否过期之类
        postAuthenticationChecks.check(user);

　　　　 ...
　　　　　// 验证成功之后返回包含完整认证信息的 Authentication 对象
        return createSuccessAuthentication(principalToReturn, authentication, user);
    }
```


如上面所述， AuthenticationProvider 通过 retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) 获取验证信息，对于我们一般所用的 DaoAuthenticationProvider 是由 UserDetailsService 专门负责获取验证信息的。

DaoAuthenticationProvider.java


```java
    protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        try {
            UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
            if (loadedUser == null) {
                throw new InternalAuthenticationServiceException("UserDetailsService returned null, which is an interface contract violation");
            }
            return loadedUser;
        }
    }
```


UserDetailsService 接口只有一个方法，loadUserByUsername(String username)，一般需要我们实现此接口方法，根据用户名加载登录认证和访问授权所需要的信息，并返回一个 UserDetails的实现类，后面登录认证和访问授权都需要用到此中的信息。


```java
public interface UserDetailsService {
    /**
     * Locates the user based on the username. In the actual implementation, the search
     * may possibly be case sensitive, or case insensitive depending on how the
     * implementation instance is configured. In this case, the <code>UserDetails</code>
     * object that comes back may have a username that is of a different case than what
     * was actually requested..
     *
     * @param username the username identifying the user whose data is required.
     *
     * @return a fully populated user record (never <code>null</code>)
     *
     * @throws UsernameNotFoundException if the user could not be found or the user has no
     * GrantedAuthority
     */
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```


UserDetails 提供了一个默认实现 User，主要包含用户名（username）、密码(password)、权限（authorities）和一些账号或密码状态的标识。

如果默认实现满足不了你的需求，可以根据需求定制自己的 UserDetails，然后在 UserDetailsService 的 loadUserByUsername 中返回即可。


```java
public class User implements UserDetails, CredentialsContainer {// ~ Instance fields
    // ================================================================================================
    private String password;
    private final String username;
    private final Set<GrantedAuthority> authorities;
    private final boolean accountNonExpired;
    private final boolean accountNonLocked;
    private final boolean credentialsNonExpired;
    private final boolean enabled;

    // ~ Constructors
    // ===================================================================================================
    public User(String username, String password,
            Collection<? extends GrantedAuthority> authorities) {
        this(username, password, true, true, true, true, authorities);
    }

　　 ...
}
```


### 退出登录

Spring Security 提供了一个默认的登出过滤器 LogoutFilter，默认拦截路径是 /logout，当访问 /logout 路径的时候，LogoutFilter 会进行退出处理。

LogoutFilter.java


```java
package org.springframework.security.web.authentication.logout;

public class LogoutFilter extends GenericFilterBean {

    // ~ Instance fields
    // ================================================================================================
    private RequestMatcher logoutRequestMatcher;
    private final LogoutHandler handler;
    private final LogoutSuccessHandler logoutSuccessHandler;

    // ~ Constructors
    // ===================================================================================================
    public LogoutFilter(LogoutSuccessHandler logoutSuccessHandler,
            LogoutHandler... handlers) {
        this.handler = new CompositeLogoutHandler(handlers);
        Assert.notNull(logoutSuccessHandler, "logoutSuccessHandler cannot be null");
        this.logoutSuccessHandler = logoutSuccessHandler;
        setFilterProcessesUrl("/logout");　　// 绑定 /logout
    }// ~ Methods
    // ========================================================================================================
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (requiresLogout(request, response)) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();this.handler.logout(request, response, auth);　　// 登出处理，可能包含session、cookie、认证信息的清理工作

            logoutSuccessHandler.onLogoutSuccess(request, response, auth);　　// 退出后的操作，可能是跳转、返回成功状态等

            return;
        }

        chain.doFilter(request, response);
    }

   ...
}
```


如下是 SecurityContextLogoutHandler 中的登出处理实现。

SecurityContextLogoutHandler.java


```java
    public void logout(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        // 让 session 失效　if (invalidateHttpSession) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                logger.debug("Invalidating session: " + session.getId());
                session.invalidate();
            }
        }
　　　　　// 清理 Security 上下文，其中包含登录认证信息
        if (clearAuthentication) {
            SecurityContext context = SecurityContextHolder.getContext();
            context.setAuthentication(null);
        }
        SecurityContextHolder.clearContext();
    }
```




## 访问授权

访问授权主要分为两种：通过URL方式的接口访问控制和方法调用的权限控制。

### 接口访问权限

在通过比如浏览器使用URL访问后台接口时，是否允许访问此URL，就是接口访问权限。

在进行接口访问时，会由 FilterSecurityInterceptor 进行拦截并进行授权。

FilterSecurityInterceptor 继承了 AbstractSecurityInterceptor 并实现了 javax.servlet.Filter 接口， 所以在URL访问的时候都会被过滤器拦截，doFilter 实现如下。

FilterSecurityInterceptor.java

```java
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {
        FilterInvocation fi = new FilterInvocation(request, response, chain);
        invoke(fi);
    }
```

doFilter 方法又调用了自身的 invoke 方法， invoke 方法又调用了父类 AbstractSecurityInterceptor 的 beforeInvocation 方法。

FilterSecurityInterceptor.java


```java
    public void invoke(FilterInvocation fi) throws IOException, ServletException {
        if ((fi.getRequest() != null)
                && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
                && observeOncePerRequest) {
            // filter already applied to this request and user wants us to observe
            // once-per-request handling, so don't re-do security checking
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        }
        else {
            // first time this request being called, so perform security checking
            if (fi.getRequest() != null && observeOncePerRequest) {
                fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
            }

            InterceptorStatusToken token = super.beforeInvocation(fi);

            try {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            }
            finally {
                super.finallyInvocation(token);
            }

            super.afterInvocation(token, null);
        }
    }
```


### 方法调用权限

在进行后台方法调用时，是否允许该方法调用，就是方法调用权限。比如在方法上添加了此类注解 @PreAuthorize("hasRole('ROLE_ADMIN')") ，Security 方法注解的支持需要在任何配置类中（如 WebSecurityConfigurerAdapter ）添加 @EnableGlobalMethodSecurity(prePostEnabled = true) 开启，才能够使用。

```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

}
```

在进行方法调用时，会由 MethodSecurityInterceptor 进行拦截并进行授权。

MethodSecurityInterceptor 继承了 AbstractSecurityInterceptor 并实现了AOP 的 org.aopalliance.intercept.MethodInterceptor 接口， 所以可以在方法调用时进行拦截。

MethodSecurityInterceptor .java


```java
    public Object invoke(MethodInvocation mi) throws Throwable {
        InterceptorStatusToken token = super.beforeInvocation(mi);

        Object result;
        try {
            result = mi.proceed();
        }
        finally {
            super.finallyInvocation(token);
        }
        return super.afterInvocation(token, result);
    }
```


我们看到，MethodSecurityInterceptor 跟 FilterSecurityInterceptor 一样， 都是通过调用父类 AbstractSecurityInterceptor 的相关方法完成授权，其中 beforeInvocation 是完成权限认证的关键。

AbstractSecurityInterceptor.java


```java
protected InterceptorStatusToken beforeInvocation(Object object) {
        ...
　　　　　// 通过 SecurityMetadataSource 获取权限配置信息，可以定制实现自己的权限信息获取逻辑
        Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);

　　　　　...

　　　　　// 确认是否经过登录认证　　　　　
        Authentication authenticated = authenticateIfRequired();

        // Attempt authorization
        try {
　　　　　　  // 通过 AccessDecisionManager 完成授权认证，默认实现是 AffirmativeBased
            this.accessDecisionManager.decide(authenticated, object, attributes);
        }
        ...
    }
```


上面代码显示 AbstractSecurityInterceptor 又是委托授权认证器 AccessDecisionManager 完成授权认证，默认实现是 AffirmativeBased， decide 方法实现如下。

AffirmativeBased.java


```java
public void decide(Authentication authentication, Object object,
            Collection<ConfigAttribute> configAttributes) throws AccessDeniedException {
        int deny = 0;

        for (AccessDecisionVoter voter : getDecisionVoters()) {
　　
　　　　　　　 // 通过各种投票策略，最终决定是否授权　
            int result = voter.vote(authentication, object, configAttributes);
switch (result) {

            case AccessDecisionVoter.ACCESS_GRANTED:
                return;

            case AccessDecisionVoter.ACCESS_DENIED:
                deny++;
                break;

            default:
                break;
            }
　　　　...
    }
```


而 AccessDecisionManager 决定授权又是通过一个授权策略集合（AccessDecisionVoter ）决定的，授权决定的原则是：

  \1. 遍历所有授权策略， 如果有其中一个返回 ACCESS_GRANTED，则同意授权。

  \2. 否则，等待遍历结束，统计 ACCESS_DENIED 个数，只要拒绝数大于1，则不同意授权。

对于接口访问授权，也就是 FilterSecurityInterceptor 管理的URL授权，默认对应的授权策略只有一个，就是 WebExpressionVoter，它的授权策略主要是根据 WebSecurityConfigurerAdapter 内配置的路径访问策略进行匹配，然后决定是否授权。

WebExpressionVoter.java


```java
/**
 * Voter which handles web authorisation decisions.
 * @author Luke Taylor
 * @since 3.0
 */
public class WebExpressionVoter implements AccessDecisionVoter<FilterInvocation> {
    private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();

    public int vote(Authentication authentication, FilterInvocation fi,
            Collection<ConfigAttribute> attributes) {
        assert authentication != null;
        assert fi != null;
        assert attributes != null;

        WebExpressionConfigAttribute weca = findConfigAttribute(attributes);

        if (weca == null) {
            return ACCESS_ABSTAIN;
        }

        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, fi);

        ctx = weca.postProcess(ctx, fi);

        return ExpressionUtils.evaluateAsBoolean(weca.getAuthorizeExpression(), ctx) ? ACCESS_GRANTED : ACCESS_DENIED;
    }

    ...
}
```


对于方法调用授权，在全局方法安全配置类里，可以看到给 MethodSecurityInterceptor 默认配置的有 RoleVoter、AuthenticatedVoter、Jsr250Voter、和 PreInvocationAuthorizationAdviceVoter，其中 Jsr250Voter、PreInvocationAuthorizationAdviceVoter 都需要打开指定的开关，才会添加支持。

GlobalMethodSecurityConfiguration.java


```java
@Configuration
public class GlobalMethodSecurityConfiguration implements ImportAware, SmartInitializingSingleton {

    ...
private MethodSecurityInterceptor methodSecurityInterceptor;
        
　　@Bean
    public MethodInterceptor methodSecurityInterceptor() throws Exception {
        this.methodSecurityInterceptor = isAspectJ()
                ? new AspectJMethodSecurityInterceptor()
                : new MethodSecurityInterceptor();
        methodSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
        methodSecurityInterceptor.setAfterInvocationManager(afterInvocationManager());
        methodSecurityInterceptor
                .setSecurityMetadataSource(methodSecurityMetadataSource());
        RunAsManager runAsManager = runAsManager();
        if (runAsManager != null) {
            methodSecurityInterceptor.setRunAsManager(runAsManager);
        }

        return this.methodSecurityInterceptor;
    }
    
    protected AccessDecisionManager accessDecisionManager() {
        List<AccessDecisionVoter<? extends Object>> decisionVoters = new ArrayList<AccessDecisionVoter<? extends Object>>();
        ExpressionBasedPreInvocationAdvice expressionAdvice = new ExpressionBasedPreInvocationAdvice();
        expressionAdvice.setExpressionHandler(getExpressionHandler());
        if (prePostEnabled()) {
            decisionVoters
                    .add(new PreInvocationAuthorizationAdviceVoter(expressionAdvice));
        }
        if (jsr250Enabled()) {
            decisionVoters.add(new Jsr250Voter());
        }
        decisionVoters.add(new RoleVoter());
        decisionVoters.add(new AuthenticatedVoter());
        return new AffirmativeBased(decisionVoters);
    }

　　...
}
```


RoleVoter 是根据角色进行匹配授权的策略。

RoleVoter.java


```java
public class RoleVoter implements AccessDecisionVoter<Object> {

　　 // RoleVoter  默认角色名以 "ROLE_" 为前缀。
    private String rolePrefix = "ROLE_";public boolean supports(ConfigAttribute attribute) {
        if ((attribute.getAttribute() != null)
                && attribute.getAttribute().startsWith(getRolePrefix())) {
            return true;
        }
        else {
            return false;
        }
    }public int vote(Authentication authentication, Object object,
            Collection<ConfigAttribute> attributes) {
        if(authentication == null) {
            return ACCESS_DENIED;
        }
        int result = ACCESS_ABSTAIN;
        Collection<? extends GrantedAuthority> authorities = extractAuthorities(authentication);
　　　　　// 逐个角色进行匹配，入股有一个匹配得上，则进行授权
        for (ConfigAttribute attribute : attributes) {
            if (this.supports(attribute)) {
                result = ACCESS_DENIED;
                // Attempt to find a matching granted authority
                for (GrantedAuthority authority : authorities) {
                    if (attribute.getAttribute().equals(authority.getAuthority())) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return result;
    }

    Collection<? extends GrantedAuthority> extractAuthorities(Authentication authentication) {
        return authentication.getAuthorities();
    }
}
```


AuthenticatedVoter 主要是针对有配置以下几个属性来决定授权的策略。

IS_AUTHENTICATED_REMEMBERED：记住我登录状态

IS_AUTHENTICATED_ANONYMOUSLY：匿名认证状态

IS_AUTHENTICATED_FULLY： 完全登录状态，即非上面两种类型

AuthenticatedVoter.java


```java
public int vote(Authentication authentication, Object object,
            Collection<ConfigAttribute> attributes) {
        int result = ACCESS_ABSTAIN;

        for (ConfigAttribute attribute : attributes) {
            if (this.supports(attribute)) {
                result = ACCESS_DENIED;
　　　　　　　　　　// 完全登录状态
                if (IS_AUTHENTICATED_FULLY.equals(attribute.getAttribute())) {
                    if (isFullyAuthenticated(authentication)) {
                        return ACCESS_GRANTED;
                    }
                }
　　　　　　　　　 // 记住我登录状态
                if (IS_AUTHENTICATED_REMEMBERED.equals(attribute.getAttribute())) {
                    if (authenticationTrustResolver.isRememberMe(authentication)
                            || isFullyAuthenticated(authentication)) {
                        return ACCESS_GRANTED;
                    }
                }
　　　　　　　　　 // 匿名登录状态
                if (IS_AUTHENTICATED_ANONYMOUSLY.equals(attribute.getAttribute())) {
                    if (authenticationTrustResolver.isAnonymous(authentication)
                            || isFullyAuthenticated(authentication)
                            || authenticationTrustResolver.isRememberMe(authentication)) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return result;
    }
```


PreInvocationAuthorizationAdviceVoter 是针对类似  @PreAuthorize("hasRole('ROLE_ADMIN')")  注解解析并进行授权的策略。

PreInvocationAuthorizationAdviceVoter.java


```java
public class PreInvocationAuthorizationAdviceVoter implements AccessDecisionVoter<MethodInvocation> {private final PreInvocationAuthorizationAdvice preAdvice;
public int vote(Authentication authentication, MethodInvocation method,
            Collection<ConfigAttribute> attributes) {

        PreInvocationAttribute preAttr = findPreInvocationAttribute(attributes);

        if (preAttr == null) {
            // No expression based metadata, so abstain
            return ACCESS_ABSTAIN;
        }

        boolean allowed = preAdvice.before(authentication, method, preAttr);

        return allowed ? ACCESS_GRANTED : ACCESS_DENIED;
    }

    private PreInvocationAttribute findPreInvocationAttribute(
            Collection<ConfigAttribute> config) {
        for (ConfigAttribute attribute : config) {
            if (attribute instanceof PreInvocationAttribute) {
                return (PreInvocationAttribute) attribute;
            }
        }
        return null;
    }
}
```


PreInvocationAuthorizationAdviceVoter 解析出注解属性配置， 然后通过调用 PreInvocationAuthorizationAdvice 的前置通知方法进行授权认证，默认实现类似 ExpressionBasedPreInvocationAdvice，通知内主要进行了内容的过滤和权限表达式的匹配。

ExpressionBasedPreInvocationAdvice.java


```java
public class ExpressionBasedPreInvocationAdvice implements PreInvocationAuthorizationAdvice {
    private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

    public boolean before(Authentication authentication, MethodInvocation mi, PreInvocationAttribute attr) {
        PreInvocationExpressionAttribute preAttr = (PreInvocationExpressionAttribute) attr;
        EvaluationContext ctx = expressionHandler.createEvaluationContext(authentication, mi);
        Expression preFilter = preAttr.getFilterExpression();
        Expression preAuthorize = preAttr.getAuthorizeExpression();

        if (preFilter != null) {
            Object filterTarget = findFilterTarget(preAttr.getFilterTarget(), ctx, mi);
            expressionHandler.filter(filterTarget, preFilter, ctx);
        }

        if (preAuthorize == null) {
            return true;
        }

        return ExpressionUtils.evaluateAsBoolean(preAuthorize, ctx);
    }

　　...
}
```


## 案例实现

接下来，我们以一个实现案例来进行说明讲解。

### 新建工程

新建一个 Spring Boot 项目 springboot-spring-security。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128154034209-1921752671.png)

### 添加依赖

添加项目依赖，主要是 Spring Security 和 JWT，另外添加 Swagger 和 fastjson 作为辅助工具。

pom.xml


```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>top.ivan.demo</groupId>
    <artifactId>springboot-spring-security</artifactId>
    <version>0.0.1</version>
    <packaging>jar</packaging>

    <name>springboot-spring-security</name>
    <description>Demo project for Spring Boot</description>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.0.4.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <project.reporting.outputEncoding>UTF-8</project.reporting.outputEncoding>
        <java.version>1.8</java.version>
        <mybatis.spring.version>1.3.2</mybatis.spring.version>
        <swagger.version>2.8.0</swagger.version>
        <jwt.version>0.9.1</jwt.version>
        <fastjson.version>1.2.48</fastjson.version>
    </properties>

    <dependencies>
           <!-- spring boot -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <!-- swagger -->
        <dependency>
            <groupId>io.springfox</groupId>
            <artifactId>springfox-swagger2</artifactId>
            <version>${swagger.version}</version>
        </dependency>
        <dependency>
            <groupId>io.springfox</groupId>
            <artifactId>springfox-swagger-ui</artifactId>
            <version>${swagger.version}</version>
        </dependency>
        <!-- spring security -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <!-- jwt -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>${jwt.version}</version>
        </dependency>
        <!-- fastjson -->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>${fastjson.version}</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```


### 启动类

启动类没什么，主要开启以下包扫描。

SpringSecurityApplication.java


```java
package com.louis.springboot.spring.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

/**
 * 启动器
 * @author Louis
 * @date Nov 28, 2018
 */
@SpringBootApplication
@ComponentScan(basePackages = "com.louis.springboot")
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }
}
```


### 跨域配置类

跨域配置类，不多说，都懂得。

CorsConfig.java


```java
package com.louis.springboot.spring.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 跨域配置
 * @author Louis
 * @date Nov 28, 2018
 */
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")    // 允许跨域访问的路径
        .allowedOrigins("*")    // 允许跨域访问的源
        .allowedMethods("POST", "GET", "PUT", "OPTIONS", "DELETE")    // 允许请求方法
        .maxAge(168000)    // 预检间隔时间
        .allowedHeaders("*")  // 允许头部设置
        .allowCredentials(true);    // 是否发送cookie
    }
}
```


### Swagger配置类

Swagger配置类，除了常规配置外，加了一个令牌属性，可以在接口调用的时候传递令牌。

SwaggerConfig.java


```java
package com.louis.springboot.spring.security.config;
import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.ParameterBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Parameter;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * Swagger配置
 * @author Louis
 * @date Nov 28, 2018
 */
@Configuration
@EnableSwagger2
public class SwaggerConfig {

    @Bean
    public Docket createRestApi(){
        // 添加请求参数，我们这里把token作为请求头部参数传入后端
        ParameterBuilder parameterBuilder = new ParameterBuilder();
        List<Parameter> parameters = new ArrayList<Parameter>();
        parameterBuilder.name("Authorization").description("令牌").modelRef(new ModelRef("string")).parameterType("header")
                .required(false).build();
        parameters.add(parameterBuilder.build());
        return new Docket(DocumentationType.SWAGGER_2).apiInfo(apiInfo()).select().apis(RequestHandlerSelectors.any())
                .paths(PathSelectors.any()).build().globalOperationParameters(parameters);
    }

    private ApiInfo apiInfo(){
        return new ApiInfoBuilder().build();
    }

}
```


加了令牌属性后的 Swagger 接口调用界面。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128155349854-989402738.png)

### 安全配置类

下面这个配置类是Spring Security的关键配置。

在这个配置类中，我们主要做了以下几个配置：

\1. 访问路径URL的授权策略，如登录、Swagger访问免登录认证等

\2. 指定了登录认证流程过滤器 JwtLoginFilter，由它来触发登录认证

\3. 指定了自定义身份认证组件 JwtAuthenticationProvider，并注入 UserDetailsService

\4. 指定了访问控制过滤器 JwtAuthenticationFilter，在授权时解析令牌和设置登录状态

\5. 指定了退出登录处理器，因为是前后端分离，防止内置的登录处理器在后台进行跳转

WebSecurityConfig.java


```java
package com.louis.springboot.spring.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

import com.louis.springboot.spring.security.security.JwtAuthenticationFilter;
import com.louis.springboot.spring.security.security.JwtAuthenticationProvider;
import com.louis.springboot.spring.security.security.JwtLoginFilter;

/**
 * Security Config
 * @author Louis
 * @date Nov 28, 2018
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;
    
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 使用自定义登录身份认证组件
        auth.authenticationProvider(new JwtAuthenticationProvider(userDetailsService));
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 禁用 csrf, 由于使用的是JWT，我们这里不需要csrf
        http.cors().and().csrf().disable()
            .authorizeRequests()
            // 跨域预检请求
            .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
            // 登录URL
            .antMatchers("/login").permitAll()
            // swagger
            .antMatchers("/swagger-ui.html").permitAll()
            .antMatchers("/swagger-resources").permitAll()
            .antMatchers("/v2/api-docs").permitAll()
            .antMatchers("/webjars/springfox-swagger-ui/**").permitAll()
            // 其他所有请求需要身份认证
            .anyRequest().authenticated();
        // 退出登录处理器
        http.logout().logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler());
        // 开启登录认证流程过滤器
        http.addFilterBefore(new JwtLoginFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
        // 访问控制时登录状态检查过滤器
        http.addFilterBefore(new JwtAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }
    
}
```


### 登录认证触发过滤器

JwtLoginFilter 是在通过访问 /login 的POST请求是被首先被触发的过滤器，默认实现是 UsernamePasswordAuthenticationFilter，它继承了 AbstractAuthenticationProcessingFilter，抽象父类的 doFilter 定义了登录认证的大致操作流程，这里我们的 JwtLoginFilter 继承了 UsernamePasswordAuthenticationFilter，并进行了两个主要内容的定制。

\1. 覆写认证方法，修改用户名、密码的获取方式，具体原因看代码注释

\2. 覆写认证成功后的操作，移除后台跳转，添加生成令牌并返回给客户端

JwtLoginFilter.java


```java
package com.louis.springboot.spring.security.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.louis.springboot.spring.security.utils.HttpUtils;
import com.louis.springboot.spring.security.utils.JwtTokenUtils;

/**
 * 启动登录认证流程过滤器
 * @author Louis
 * @date Nov 28, 2018
 */
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter {
    
    public JwtLoginFilter(AuthenticationManager authManager) {
        setAuthenticationManager(authManager);
    }
    
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        // POST 请求 /login 登录时拦截， 由此方法触发执行登录认证流程，可以在此覆写整个登录认证逻辑
        super.doFilter(req, res, chain); 
    }
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 可以在此覆写尝试进行登录认证的逻辑，登录成功之后等操作不再此方法内
        // 如果使用此过滤器来触发登录认证流程，注意登录请求数据格式的问题
        // 此过滤器的用户名密码默认从request.getParameter()获取，但是这种
        // 读取方式不能读取到如 application/json 等 post 请求数据，需要把
        // 用户名密码的读取逻辑修改为到流中读取request.getInputStream()

        String body = getBody(request);
        JSONObject jsonObject = JSON.parseObject(body);
        String username = jsonObject.getString("username");
        String password = jsonObject.getString("password");

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        username = username.trim();

        JwtAuthenticatioToken authRequest = new JwtAuthenticatioToken(username, password);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    
    }
    
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        // 存储登录认证信息到上下文
        SecurityContextHolder.getContext().setAuthentication(authResult);
        // 记住我服务
        getRememberMeServices().loginSuccess(request, response, authResult);
        // 触发事件监听器
        if (this.eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, this.getClass()));
        }
        // 生成并返回token给客户端，后续访问携带此token
        JwtAuthenticatioToken token = new JwtAuthenticatioToken(null, null, JwtTokenUtils.generateToken(authResult));
        HttpUtils.write(response, token);
    }
    
    /** 
     * 获取请求Body
     * @param request
     * @return
     */
    public String getBody(HttpServletRequest request) {
        StringBuilder sb = new StringBuilder();
        InputStream inputStream = null;
        BufferedReader reader = null;
        try {
            inputStream = request.getInputStream();
            reader = new BufferedReader(new InputStreamReader(inputStream, Charset.forName("UTF-8")));
            String line = "";
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return sb.toString();
    }
}
```


### 登录控制器

除了使用上面的登录认证过滤器拦截 /login Post请求之外，我们也可以不使用上面的过滤器，通过自定义登录接口实现，只要在登录接口手动触发登录流程并生产令牌即可。

其实 Spring Security 的登录认证过程只需 调用 AuthenticationManager 的 authenticate(Authentication authentication) 方法，最终返回认证成功的 Authentication 实现类并存储到SpringContexHolder 上下文即可，这样后面授权的时候就可以从 SpringContexHolder 中获取登录认证信息，并根据其中的用户信息和权限信息决定是否进行授权。

LoginController.java


```java
package com.louis.springboot.spring.security.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.louis.springboot.spring.security.security.JwtAuthenticatioToken;
import com.louis.springboot.spring.security.utils.SecurityUtils;
import com.louis.springboot.spring.security.vo.HttpResult;
import com.louis.springboot.spring.security.vo.LoginBean;

/**
 * 登录控制器
 * @author Louis
 * @date Nov 28, 2018
 */
@RestController
public class LoginController {

    @Autowired
    private AuthenticationManager authenticationManager;

    /**
     * 登录接口
     */
    @PostMapping(value = "/login")
    public HttpResult login(@RequestBody LoginBean loginBean, HttpServletRequest request) throws IOException {
        String username = loginBean.getUsername();
        String password = loginBean.getPassword();
        
        // 系统登录认证
        JwtAuthenticatioToken token = SecurityUtils.login(request, username, password, authenticationManager);
                
        return HttpResult.ok(token);
    }

}
```


注意：如果使用此登录控制器触发登录认证，需要禁用登录认证过滤器，即将 WebSecurityConfig 中的以下配置项注释即可，否则访问登录接口会被过滤拦截，执行不会再进入此登录接口，大家根据使用习惯二选一即可。

```
// 开启登录认证流程过滤器，如果使用LoginController的login接口, 需要注释掉此过滤器，根据使用习惯二选一即可
http.addFilterBefore(new JwtLoginFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
```

如下是登录认证的逻辑， 可以看到部分逻辑跟上面的登录认证过滤器差不多。

\1. 执行登录认证过程，通过调用 AuthenticationManager 的 authenticate(token) 方法实现

\2. 将认证成功的认证信息存储到上下文，供后续访问授权的时候获取使用

\3. 通过JWT生成令牌并返回给客户端，后续访问和操作都需要携带此令牌

SecurityUtils.java


```java
/**
 * Security相关操作
 * @author Louis
 * @date Nov 28, 2018
 */
public class SecurityUtils {

    /**
     * 系统登录认证
     * @param request
     * @param username
     * @param password
     * @param authenticationManager
     * @return
     */
    public static JwtAuthenticatioToken login(HttpServletRequest request, String username, String password, AuthenticationManager authenticationManager) {
        JwtAuthenticatioToken token = new JwtAuthenticatioToken(username, password);
        token.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        // 执行登录认证过程
        Authentication authentication = authenticationManager.authenticate(token);
        // 认证成功存储认证信息到上下文
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // 生成令牌并返回给客户端
        token.setToken(JwtTokenUtils.generateToken(authentication));
        return token;
    }
　　
　　...

}
```


### 令牌生成器

我们令牌是使用JWT生成的，下面是令牌生成的简要逻辑，详细参见源码。

JwtTokenUtils.java


```java
/**
 * JWT工具类
 * @author Louis
 * @date Nov 28, 2018
 */
public class JwtTokenUtils implements Serializable {

    .../**
     * 生成令牌
     *
     * @param userDetails 用户
     * @return 令牌
     */
    public static String generateToken(Authentication authentication) {
        Map<String, Object> claims = new HashMap<>(3);
        claims.put(USERNAME, SecurityUtils.getUsername(authentication));
        claims.put(CREATED, new Date());
        claims.put(AUTHORITIES, authentication.getAuthorities());
        return generateToken(claims);
    }

    /**
     * 从数据声明生成令牌
     *
     * @param claims 数据声明
     * @return 令牌
     */
    private static String generateToken(Map<String, Object> claims) {
        Date expirationDate = new Date(System.currentTimeMillis() + EXPIRE_TIME);
        return Jwts.builder().setClaims(claims).setExpiration(expirationDate).signWith(SignatureAlgorithm.HS512, SECRET).compact();
    }

　　...

}
```


### 登录身份认证组件

上面说到登录认证是通过调用 AuthenticationManager 的 authenticate(token) 方法实现的，而 AuthenticationManager 又是通过调用 AuthenticationProvider 的 authenticate(Authentication authentication) 来完成认证的，所以通过定制 AuthenticationProvider 也可以完成各种自定义的需求，我们这里只是简单的继承 DaoAuthenticationProvider 展示如何自定义，具体的大家可以根据各自的需求按需定制。

JwtAuthenticationProvider.java


```java
package com.louis.springboot.spring.security.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * 身份验证提供者
 * @author Louis
 * @date Nov 20, 2018
 */
public class JwtAuthenticationProvider extends DaoAuthenticationProvider {

    public JwtAuthenticationProvider(UserDetailsService userDetailsService) {
        setUserDetailsService(userDetailsService);
        setPasswordEncoder(new BCryptPasswordEncoder());
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 可以在此处覆写整个登录认证逻辑
        return super.authenticate(authentication);
    }
    
    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        // 可以在此处覆写密码验证逻辑
        super.additionalAuthenticationChecks(userDetails, authentication);
    }

}
```


### 认证信息获取服务

通过跟踪代码运行，我们发现像默认使用的 DaoAuthenticationProvider，在认证的使用都是通过一个叫 UserDetailsService 的来获取用户认证所需信息的。

AbstractUserDetailsAuthenticationProvider 定义了在 authenticate 方法中通过 retrieveUser 方法获取用户信息，子类 DaoAuthenticationProvider 通过 UserDetailsService 来进行获取， 一般情况，这个 UserDetailsService 需要我们自定义，实现从用户服务获取用户和权限信息封装到 UserDetails 的实现类。

AbstractUserDetailsAuthenticationProvider.java


```java
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
　　　　　...
if (user == null) {
            cacheWasUsed = false;
            try {
                user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication);
            }
     
        ...return createSuccessAuthentication(principalToReturn, authentication, user);
    }
```


DaoAuthenticationProvider.java


```java
    protected final UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        try {

            UserDetails loadedUser = this.getUserDetailsService().loadUserByUsername(username);
       return loadedUser;
        }
        ...
    }
```


我们自定义的 UserDetailsService，从我们的用户服务 UserService 中获取用户和权限信息。

UserDetailsServiceImpl.java


```java
package com.louis.springboot.spring.security.security;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.louis.springboot.spring.security.model.User;
import com.louis.springboot.spring.security.service.UserService;

/**
 * 用户登录认证信息查询
 * @author Louis
 * @date Nov 20, 2018
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("该用户不存在");
        }
        // 用户权限列表，根据用户拥有的权限标识与如 @PreAuthorize("hasAuthority('sys:menu:view')") 标注的接口对比，决定是否可以调用接口
        Set<String> permissions = userService.findPermissions(username);
        List<GrantedAuthority> grantedAuthorities = permissions.stream().map(GrantedAuthorityImpl::new).collect(Collectors.toList());
        return new JwtUserDetails(username, user.getPassword(), grantedAuthorities);
    }
}
```


一般而言，定制 UserDetailsService 就可以满足大部分需求了，在 UserDetailsService 满足不了我们的需求的时候考虑定制 AuthenticationProvider。

如果直接定制UserDetailsService ，而不自定义 AuthenticationProvider，可以直接在配置文件 WebSecurityConfig 中这样配置。

WebSecurityConfig.java

```java
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 指定自定义的获取信息获取服务
        auth.userDetailsService(userDetailsService)
    }
```

### 用户认证信息

上面 UserDetailsService 加载好用户认证信息后会封装认证信息到一个 UserDetails 的实现类。

默认实现是 User 类，我们这里没有特殊需要，简单继承即可，复杂需求可以在此基础上进行拓展。

JwtUserDetails.java


```java
package com.louis.springboot.spring.security.security;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * 安全用户模型
 * @author Louis
 * @date Nov 28, 2018
 */
public class JwtUserDetails extends User {

    private static final long serialVersionUID = 1L;

    public JwtUserDetails(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        this(username, password, true, true, true, true, authorities);
    }
    
    public JwtUserDetails(String username, String password, boolean enabled, boolean accountNonExpired,
            boolean credentialsNonExpired, boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }

}
```


### 用户操作代码

简单的用户模型，包含用户名密码。

User.java


```java
package com.louis.springboot.spring.security.model;

/**
 * 用户模型
 * @author Louis
 * @date Nov 28, 2018
 */
public class User {

    private Long id;
    
    private String username;

    private String password;

    ...

}
```


用户服务接口，只提供简单的用户查询和权限查询接口用于模拟。

UserService.java


```java
/**
 * 用户管理
 * @author Louis
 * @date Nov 28, 2018
 */
public interface UserService {

    /**
     * 根据用户名查找用户
     * @param username
     * @return
     */
    User findByUsername(String username);

    /**
     * 查找用户的菜单权限标识集合
     * @param userName
     * @return
     */
    Set<String> findPermissions(String username);

}
```


用户服务实现，只简单获取返回模拟数据，实际场景根据情况从DAO获取即可。

SysUserServiceImpl.java


```java
@Service
public class SysUserServiceImpl implements UserService {

    @Override
    public User findByUsername(String username) {
        User user = new User();
        user.setId(1L);
        user.setUsername(username);
        String password = new BCryptPasswordEncoder().encode("123");
        user.setPassword(password);
        return user;
    }

    @Override
    public Set<String> findPermissions(String username) {
        Set<String> permissions = new HashSet<>();
        permissions.add("sys:user:view");
        permissions.add("sys:user:add");
        permissions.add("sys:user:edit");
        return permissions;
    }

}
```


用户控制器，提供三个测试接口，其中权限列表中未包含删除接口定义的权限（'sys:user:delete'），登录之后也将无权限调用。

UserController.java


```java
/**
 * 用户控制器
 * @author Louis 
 * @date Oct 31, 2018
 */
@RestController
@RequestMapping("user")
public class UserController {

    
    @PreAuthorize("hasAuthority('sys:user:view')")
    @GetMapping(value="/findAll")
    public HttpResult findAll() {
        return HttpResult.ok("the findAll service is called success.");
    }
    
    @PreAuthorize("hasAuthority('sys:user:edit')")
    @GetMapping(value="/edit")
    public HttpResult edit() {
        return HttpResult.ok("the edit service is called success.");
    }
    
    @PreAuthorize("hasAuthority('sys:user:delete')")
    @GetMapping(value="/delete")
    public HttpResult delete() {
        return HttpResult.ok("the delete service is called success.");
    }

}
```


### 登录认证检查过滤器

访问接口的时候，登录认证检查过滤器 JwtAuthenticationFilter 会拦截请求校验令牌和登录状态，并根据情况设置登录状态。

JwtAuthenticationFilter.java


```java
/**
 * 登录认证检查过滤器
 * @author Louis
 * @date Nov 20, 2018
 */
public class JwtAuthenticationFilter extends BasicAuthenticationFilter {
    
    @Autowired
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 获取token, 并检查登录状态
        SecurityUtils.checkAuthentication(request);
        chain.doFilter(request, response);
    }
    
}
```


SecurityUtils.java


```java
    /**
     * 获取令牌进行认证
     * @param request
     */
    public static void checkAuthentication(HttpServletRequest request) {
        // 获取令牌并根据令牌获取登录认证信息
        Authentication authentication = JwtTokenUtils.getAuthenticationeFromToken(request);
        // 设置登录认证信息到上下文
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
```


JwtTokenUtils.java


```java
    /**
     * 根据请求令牌获取登录认证信息
     * @param token 令牌
     * @return 用户名
     */
    public static Authentication getAuthenticationeFromToken(HttpServletRequest request) {
        Authentication authentication = null;
        // 获取请求携带的令牌
        String token = JwtTokenUtils.getToken(request);
        if(token != null) {
            // 请求令牌不能为空
            if(SecurityUtils.getAuthentication() == null) {
                // 上下文中Authentication为空
                Claims claims = getClaimsFromToken(token);
                if(claims == null) {
                    return null;
                }
                String username = claims.getSubject();
                if(username == null) {
                    return null;
                }
                if(isTokenExpired(token)) {
                    return null;
                }
                Object authors = claims.get(AUTHORITIES);
                List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
                if (authors != null && authors instanceof List) {
                    for (Object object : (List) authors) {
                        authorities.add(new GrantedAuthorityImpl((String) ((Map) object).get("authority")));
                    }
                }
                authentication = new JwtAuthenticatioToken(username, null, authorities, token);
            } else {
                if(validateToken(token, SecurityUtils.getUsername())) {
                    // 如果上下文中Authentication非空，且请求令牌合法，直接返回当前登录认证信息
                    authentication = SecurityUtils.getAuthentication();
                }
            }
        }
        return authentication;
    }
```


### 接口测试

找到 SpringSecurityApplication， 启动程序， 访问 <http://localhost:8080/swagger-ui.html>，进入Swagger。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128173706668-177381559.png)

 

我们先再未登录没有令牌的时候直接访问接口，发现都返回无权限，禁止访问的结果。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128173840193-199335952.png)

返回拒绝访问结果。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128174042582-676639129.png)

 打开 LoginController，输入我们用户名和密码（username:amdin, password:123）

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128174231451-1027667004.png)

 登录成功之后，成功返回令牌，如下图所示。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128174436613-252448914.png)

拷贝返回的令牌，粘贴到令牌参数输入框，再次访问 /user/edit 接口。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128174642788-1883486292.png)

这个时候，成功的返回了结果： the edit service is called success.

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128174754351-925193390.png)

同样的，拷贝返回的令牌，粘贴到令牌参数输入框，访问 /user/delete 接口。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128174924465-934756567.png)

发现还是返回拒绝访问的结果，那是因为访问这个接口需要 'sys:user:delete' 权限，而我们之前返回的权限列表中并没有包含，所以授权访问失败。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128175018727-518353637.png)

我们修改一下 SysUserServiceImpl，添加上‘sys:user:delete’ 权限，重新登录，再次访问一遍。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128175401465-494777099.png)

发现删除接口也可以访问了，记住务必要重新调用登录接口，获取令牌后拷贝到删除接口，再次访问删除接口。

![img](https://img2018.cnblogs.com/blog/616891/201811/616891-20181128175606389-1013803667.png)

到此，Spring Security 的讲解就结束了，本人知识有限，有不正确的地方，烦请指正，不尽感激。

