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

public void savePublicKey() { 

    try (FileOutputStream fos = new FileOutputStream("public.key")) {
        fos.write(publicKey.getEncoded());
    }

}


    
    
}
