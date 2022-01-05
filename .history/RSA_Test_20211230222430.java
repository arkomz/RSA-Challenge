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
import org.quicktheories.WithQuickTheories;

class RSA_Test implements WithQuickTheories {

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

  @Test
  void splitAndJoinQuorate() {
    // All distinct subsets of parts of cardinality greater than or equal to the threshold should
    // join to recover the original secret.
    qt().forAll(integers().between(2, 5), integers().between(1, 5), byteArrays(1, 300))
        .asWithPrecursor((k, extra, secret) -> new Scheme(new SecureRandom(), k + extra, k))
        .check(
            (k, e, secret, scheme) -> {
              final Map<Integer, byte[]> parts = scheme.split(secret);
              return Sets.powerSet(parts.entrySet()).stream()
                  .parallel()
                  .filter(s -> s.size() >= k)
                  .map(entries -> join(scheme, entries))
                  .allMatch(s -> Arrays.equals(s, secret));
            });
  }

  @Test
  void splitAndJoinInquorate() {
    // All distinct subsets of parts of cardinality less than the threshold should never join to
    // recover the original secret. Only check larger secrets to avoid false positives.
    qt().forAll(integers().between(2, 5), integers().between(1, 5), byteArrays(3, 300))
        .asWithPrecursor((k, extra, secret) -> new Scheme(new SecureRandom(), k + extra, k))
        .check(
            (k, e, secret, scheme) -> {
              final Map<Integer, byte[]> parts = scheme.split(secret);
              return Sets.powerSet(parts.entrySet()).stream()
                  .parallel()
                  .filter(s -> s.size() < k && !s.isEmpty())
                  .map(entries -> join(scheme, entries))
                  .noneMatch(s -> Arrays.equals(s, secret));
            });
  }

  private byte[] join(Scheme scheme, Set<Map.Entry<Integer, byte[]>> entries) {
    final Map<Integer, byte[]> m = new HashMap<>();
    entries.forEach(v -> m.put(v.getKey(), v.getValue()));
    return scheme.join(m);
  }
}