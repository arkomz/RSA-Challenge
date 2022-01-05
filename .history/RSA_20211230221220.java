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






}


    

