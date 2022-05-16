import org.apache.syncope.sra.session.SessionUtils;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;

import static org.junit.jupiter.api.Assertions.assertEquals;


public class TestSessionUtils {
    @Test
    public void dummyTest(){
         ServerWebExchangeMatcher matcher = SessionUtils.authInSession();
         boolean notNull = matcher != null;
         assertEquals(true, notNull);
    }
}
