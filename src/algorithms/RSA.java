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

import common.Helper;
    

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
//		  RSAPublicKey puk = (RSAPublicKey)(Helper.loadPublicKey("Keys/CA/public_key.der"));
//		  RSAPrivateKey prk= (RSAPrivateKey)(Helper.loadPrivateKey("Keys/CA/private_key.der"));
		  
		  RSAPublicKey puk = (RSAPublicKey)keyPair.getPublic();
		  RSAPrivateKey prk= (RSAPrivateKey)keyPair.getPrivate();
		  
		  RSA key = new RSA(puk.getModulus());
	//      System.out.println(key);
	 
	      // create random message, encrypt and decrypt
//	      BigInteger message = new BigInteger(N-1, random);
		  SecureRandom sr = new SecureRandom();

		  
		byte[] session = new byte[32];
//			byte[] iv = new byte[16];
		for(int i = 0 ; i < 50 ; i++){
		sr.nextBytes(session);

	      BigInteger message = new BigInteger(1, session);
//	      System.out.println(message.toByteArray().length);
	
	      //// create message by converting string to integer
	      // String s = "test";
	      // byte[] bytes = s.getBytes();
	      // BigInteger message = new BigInteger(s);
	      
	      BigInteger encrypt = key.encrypt(message, prk.getPrivateExponent());
//	      System.out.println(encrypt.toByteArray().length);
	      BigInteger decrypt = key.decrypt(encrypt, puk.getPublicExponent());
	      System.out.println("message   = " + message);
	      System.out.println("encrpyted = " + encrypt);
	      System.out.println("decrypted = " + decrypt);}
	  }
	  catch(Exception e){
		  e.printStackTrace();
	  }
   }
   
   public static void print(byte[] data){
//	   System.out.println("RSA print");
		for (byte b : data) {
			   System.out.format("%x ", b);
		}
		System.out.println();
	}
}
