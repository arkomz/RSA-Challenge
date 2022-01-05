import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.util.*;

public class RSA {

public KeyPairGenerator generator;
public KeyPair pair;
public PrivateKey privateKey;
public PublicKey publicKey;
private final SecureRandom random;
private final int n;
private final int k;


public RSA(SecureRandom random, int n, int k) {
    generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    pair =  generator.generateKeyPair();
    privateKey = pair.getPrivate();
    publicKey = pair.getPublic();
    this.random = random;
    checkArgument(k > 1, "K must be > 1");
    checkArgument(n >= k, "N must be >= K");
    checkArgument(n <= 255, "N must be <= 255");
    this.n = n;
    this.k = k;

}

public void saveKeyPair(OutputStream privateKeyOutput, OutputStream publicKeyOutput) throws IOException { 

 // Store Public Key.
 X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
   publicKey.getEncoded());
 publicKeyOutput.write(x509EncodedKeySpec.getEncoded());
 // Store Private Key.
 PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
   privateKey.getEncoded());
 privateKeyOutput.write(pkcs8EncodedKeySpec.getEncoded());
}

private static byte[] encodePrivateKey(PrivateKey privateKey) throws InvalidKeyException {
  byte[] encodedPrivateKey = null;
  if ("X.509".equals(privateKey.getFormat())) {
    encodedPrivateKey = privateKey.getEncoded();
  }
  if (encodedPrivateKey == null) {
    try {
      encodedPrivateKey =
          KeyFactory.getInstance(privateKey.getAlgorithm())
              .getKeySpec(privateKey, X509EncodedKeySpec.class)
              .getEncoded();
    } catch (NoSuchAlgorithmException e) {
      throw new InvalidKeyException(
          "Failed to obtain X.509 encoded form of public key " + privateKey
              + " of class " + privateKey.getClass().getName(),
          e);
    } catch (InvalidKeySpecException e) {
      throw new InvalidKeyException(
          "Failed to obtain X.509 encoded form of public key " + privateKey
              + " of class " + privateKey.getClass().getName(),
          e);
    }
  }
  if ((encodedPrivateKey == null) || (encodedPrivateKey.length == 0)) {
    throw new InvalidKeyException(
        "Failed to obtain X.509 encoded form of public key " + privateKey
            + " of class " + privateKey.getClass().getName());
  }
  return encodedPrivateKey;
}

public Map<Integer, byte[]> split(byte[] secret) {
  // generate part values
  final byte[][] values = new byte[n][secret.length];
  for (int i = 0; i < secret.length; i++) {
    // for each byte, generate a random polynomial, p
    final byte[] p = GF256.generate(random, k - 1, secret[i]);
    for (int x = 1; x <= n; x++) {
      // each part's byte is p(partId)
      values[x - 1][i] = GF256.eval(p, (byte) x);
    }
  }

  // return as a set of objects
  final Map<Integer, byte[]> parts = new HashMap<>(n());
  for (int i = 0; i < values.length; i++) {
    parts.put(i + 1, values[i]);
  }
  return Collections.unmodifiableMap(parts);
}

/**
 * Joins the given parts to recover the original secret.
 *
 * <p><b>N.B.:</b> There is no way to determine whether or not the returned value is actually the
 * original secret. If the parts are incorrect, or are under the threshold value used to split the
 * secret, a random value will be returned.
 *
 * @param parts a map of part IDs to part values
 * @return the original secret
 * @throws IllegalArgumentException if {@code parts} is empty or contains values of varying
 *     lengths
 */
public byte[] join(Map<Integer, byte[]> parts) {
  checkArgument(parts.size() > 0, "No parts provided");
  final int[] lengths = parts.values().stream().mapToInt(v -> v.length).distinct().toArray();
  checkArgument(lengths.length == 1, "Varying lengths of part values");
  final byte[] secret = new byte[lengths[0]];
  for (int i = 0; i < secret.length; i++) {
    final byte[][] points = new byte[parts.size()][2];
    int j = 0;
    for (Map.Entry<Integer, byte[]> part : parts.entrySet()) {
      points[j][0] = part.getKey().byteValue();
      points[j][1] = part.getValue()[i];
      j++;
    }
    secret[i] = GF256.interpolate(points);
  }
  return secret;
}

/**
 * The number of parts the scheme will generate when splitting a secret.
 *
 * @return {@code N}
 */
public int n() {
  return n;
}

/**
 * The number of parts the scheme will require to re-create a secret.
 *
 * @return {@code K}
 */
public int k() {
  return k;
}

@Override
public boolean equals(Object o) {
  if (this == o) {
    return true;
  }
  if (!(o instanceof Scheme)) {
    return false;
  }
  final Scheme scheme = (Scheme) o;
  return n == scheme.n && k == scheme.k && Objects.equals(random, scheme.random);
}

@Override
public int hashCode() {
  return Objects.hash(random, n, k);
}

@Override
public String toString() {
  return new StringJoiner(", ", Scheme.class.getSimpleName() + "[", "]")
      .add("random=" + random)
      .add("n=" + n)
      .add("k=" + k)
      .toString();
}

private static void checkArgument(boolean condition, String message) {
  if (!condition) {
    throw new IllegalArgumentException(message);
  }
}
}






    

