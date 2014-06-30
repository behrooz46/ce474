package algorithms;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
    

public class RSA {
   private final static BigInteger one      = new BigInteger("1");
   private final static SecureRandom random = new SecureRandom();

   private BigInteger mod;


   public RSA(BigInteger mod){
	   this.mod = mod;
   }

   public BigInteger encrypt(BigInteger message, BigInteger publicKey) {
      return message.modPow(publicKey, mod);
   }

   public BigInteger decrypt(BigInteger encrypted, BigInteger privateKey) {
      return encrypted.modPow(privateKey, mod);
   }

   public static void main(String[] args) {
	  try{
		  Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		  KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
		  keyPairGenerator.initialize(1024, new SecureRandom());
		  
		  KeyPair keyPair = keyPairGenerator.generateKeyPair();
		  RSAPublicKey puk = (RSAPublicKey)keyPair.getPublic();
		  RSAPrivateKey prk= (RSAPrivateKey)keyPair.getPrivate();
		  
		  int N = 1024;
	      RSA key = new RSA(puk.getModulus());
	//      System.out.println(key);
	 
	      // create random message, encrypt and decrypt
	      BigInteger message = new BigInteger(N-1, random);
	
	      //// create message by converting string to integer
	      // String s = "test";
	      // byte[] bytes = s.getBytes();
	      // BigInteger message = new BigInteger(s);
	      
	      BigInteger encrypt = key.encrypt(message, puk.getPublicExponent());
	      BigInteger decrypt = key.decrypt(encrypt, prk.getPrivateExponent());
	      System.out.println("message   = " + message);
	      System.out.println("encrpyted = " + encrypt);
	      System.out.println("decrypted = " + decrypt);
	  }
	  catch(Exception e){
		  e.printStackTrace();
	  }
   }
   
   public static void print(byte[] data){
		for (byte b : data) {
			   System.out.format("%x ", b);
		}
	}
}
