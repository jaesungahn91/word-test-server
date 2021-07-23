package js.toy.vocabulary.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;


@RequiredArgsConstructor
@Component
@Slf4j
public class JwtTokenProvider {

    /**
     * TODO:
     * 1. 이미 인코딩한 문자열을 key로 사용할건지 init시 인코딩을 할건지 보안상 문제 없는지 확인
     * 2. jwtSecretKey, jwtExpirationMs 을 프로퍼티로 빼내기
     */

    private String jwtSecretKey = "webfirewood";

    /* 토큰 유효시간 */
//    private long jwtExpirationMs = 30 * 60 * 1000L;
    private long jwtExpirationMs = 30 * 1000L;


    /* 객체 초기화, secretKey를 Base64로 인코딩한다. */
    @PostConstruct
    protected void init() {
        jwtSecretKey = Base64.getEncoder().encodeToString(jwtSecretKey.getBytes());
    }

    public String createToken(Authentication authentication) {
        SecurityUser securityUser = (SecurityUser) authentication.getPrincipal();

        Date now = new Date();
        return Jwts.builder()
                .setSubject(securityUser.getUsername())  // 정보 저장
                .setIssuer("vocabulary")
                .setIssuedAt(now)   // 토큰 발행 시간 정보
                .claim("name", securityUser.getUsername())
                .claim("seq", securityUser.getSeq())
                .setExpiration(new Date(now.getTime() + jwtExpirationMs))    // set Expire Time
                .signWith(SignatureAlgorithm.HS256, jwtSecretKey)      // 사용할 암호화 알고리즘과
                // signature에 들어갈 secret값 세팅
                .compact();
    }

    /* request에서 jwt 토큰 가져오기 `*/
    public String getJwtFromRequest(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        return getJwtFromAuthoriation(authorization);
    }

    public String getJwtFromAuthoriation(String authorization) {
        if (StringUtils.isNotBlank(authorization) && authorization.startsWith("Bearer ")) {
            return authorization.substring(7);
        }
        return null;
    }

    public Long getSeqFromToken(String token) {
        return getAllClaimsFromToken(token).get("seq", Long.class);
    }

    /* 유저 아이디 가져오기 */
    public String getEmailFromToken(String token) {
        return getAllClaimsFromToken(token).getSubject();
    }

    /* 만료 데이터 검색 */
    public Date getExpirationDateFromToken(String token) {
        return getAllClaimsFromToken(token).getExpiration();
    }

    /* token 만료 여부 */
    public boolean isTokenExpired(String token) {
        Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    /* token 벨리데이션 */
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(jwtSecretKey).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            log.error("=====================================================");
            log.error("[JWT TOKEN is not valid] " + token);
            log.error(e.getMessage());
            log.error("=====================================================");
            e.printStackTrace();
        }
        return false;
    }

    /* secretkey를 이용하여 token에 저장된 정보(claim) 가져오기 */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(jwtSecretKey).parseClaimsJws(token).getBody();
    }
}
