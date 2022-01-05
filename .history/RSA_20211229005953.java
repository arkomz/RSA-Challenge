import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class RSA {

public KeyPairGenerator generator;
public KeyPair pair;
public PrivateKey privateKey;
public PublicKey publicKey;


public RSA() {
    generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    pair =  generator.generateKeyPair();
    privateKey = pair.getPrivate();
    publicKey = pair.getPublic();
}

public void saveKeyPair(OutputStream privateKeyOutput, OutputStream publicKeyOutput) throws IOException{ 

 // Store Public Key.
 X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
   publicKey.getEncoded());
 publicKeyOutput.write(x509EncodedKeySpec.getEncoded());
 // Store Private Key.
 PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
   privateKey.getEncoded());
 privateKeyOutput.write(pkcs8EncodedKeySpec.getEncoded());
}







}


    

