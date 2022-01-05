
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

class RSA_Test {


  @Test
  void hasProperties() {
    final RSA scheme = new RSA(new SecureRandom(), 2, 5);

    assertThat(scheme.n()).isEqualTo(5);
    assertThat(scheme.k()).isEqualTo(2);
  }

  @Test
  void tooManyShares() {
    assertThatThrownBy(() -> new Scheme(new SecureRandom(), 2_000, 3))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void thresholdTooLow() {
    assertThatThrownBy(() -> new Scheme(new SecureRandom(), 1, 1))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void thresholdTooHigh() {
    assertThatThrownBy(() -> new Scheme(new SecureRandom(), 1, 2))
        .isInstanceOf(IllegalArgumentException.class);
  }

 


  private byte[] join(RSA scheme, Set<Map.Entry<Integer, byte[]>> entries) {
    final Map<Integer, byte[]> m = new HashMap<>();
    entries.forEach(v -> m.put(v.getKey(), v.getValue()));
    return scheme.join(m);
  }
}