import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Sets;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import static org.junit.Assert.*;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class RSA_Test {

  @Test
  void hasProperties() {
    final RSA scheme = new RSA(new SecureRandom(), 5, 3);

    assertThat(scheme.n()).isEqualTo(5);
    assertThat(scheme.k()).isEqualTo(3);
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

  @Test
  void joinEmptyParts() {
    assertThatThrownBy(() -> new Scheme(new SecureRandom(), 3, 2).join(Collections.emptyMap()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void joinIrregularParts() {
    final byte[] one = new byte[] {1};
    final byte[] two = new byte[] {1, 2};

    assertThatThrownBy(
            () -> new Scheme(new SecureRandom(), 3, 2).join(ImmutableMap.of(1, one, 2, two)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void splitAndJoinSingleByteSecret() {
    final Scheme scheme = new Scheme(new SecureRandom(), 8, 3);
    final byte[] secret = "x".getBytes(StandardCharsets.UTF_8);

    assertThat(scheme.join(scheme.split(secret))).containsExactly(secret);
  }

  @Test
  void splitAndJoinMoreThanByteMaxValueParts() {
    final Scheme scheme = new Scheme(new SecureRandom(), 200, 3);
    final byte[] secret = "x".getBytes(StandardCharsets.UTF_8);

    assertThat(scheme.join(scheme.split(secret))).containsExactly(secret);
  }

  private byte[] join(Scheme scheme, Set<Map.Entry<Integer, byte[]>> entries) {
    final Map<Integer, byte[]> m = new HashMap<>();
    entries.forEach(v -> m.put(v.getKey(), v.getValue()));
    return scheme.join(m);
  }
}