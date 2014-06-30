package common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import sun.security.provider.SecureRandom;

import ca.SignServer;
import algorithms.*;

public class Msg implements Serializable {
	private static final long serialVersionUID = -8154976896133585345L;

	public static final int Encryption_NONE = 0, Encryption_RSA = 1, Encryption_AES = 2 ;
	
	public int encryptionMethod;
	
	public int status ; 
	public HashMap<String, byte[]> map ;
	public byte[] sign ;

	public Msg() {
		// TODO Auto-generated constructor stub
		map = new HashMap<String, byte[]>();
	}
	
	
	public void sign(byte[] key) {
		try{
			RSAPrivateKey pk = (RSAPrivateKey)Helper.arrayToPrivateKey(key);
			algorithms.RSA rsa = new algorithms.RSA(pk.getModulus());
			
			int len = 0;
			for(Map.Entry<String, byte[]> ent : map.entrySet()){
				len += ent.getValue().length;
			}

			byte[] res = new byte[len];
			
			int prev = 0;
			for(Map.Entry<String, byte[]> ent : map.entrySet()){
//				System.out.println(ent.getKey());
				System.arraycopy(ent.getValue(), 0, res, prev, ent.getValue().length);
				prev += ent.getValue().length;
			}
			
			System.out.println("res in sign:");
			RSA.print(res);
			
			BigInteger msg = new BigInteger(1, SHA256.hash(res));
			sign = rsa.encrypt(msg, pk.getPrivateExponent()).toByteArray() ;
		}
		catch(Exception e){
			System.err.println("Error while sigining");
		}
	}


	public void encrypt(byte[] key, KeyType type) {
		// encrypt each section separately
		try{
			switch (encryptionMethod) {
			case Encryption_RSA:
				RSAKey pk;
				
				if(type == KeyType.Public){
					pk = (RSAPublicKey)(Helper.arrayToPublicKey(key));
				}
				else{
					pk = (RSAPrivateKey)(Helper.arrayToPrivateKey(key));
				}
				
				  
				algorithms.RSA rsa = new RSA(pk.getModulus());
				
				HashMap<String, byte[]> res = new HashMap<String, byte[]>();
				
				for(Map.Entry<String, byte[]> ent : map.entrySet()){
					byte[] enc = rsa.encrypt(new BigInteger(1, ent.getValue()), 
							type == KeyType.Private ? ((RSAPrivateKey)pk).getPrivateExponent(): 
								((RSAPublicKey)pk).getPublicExponent()).toByteArray();
					if(type == KeyType.Private && enc[0] == 0){
						byte[] tmp = enc;
						enc = new byte[tmp.length - 1];
						System.arraycopy(tmp, 1, enc, 0, enc.length);
					}
					res.put(ent.getKey(),enc);
				}
				
				map = res;
				
				break;
			case Encryption_AES:
				break;
			case Encryption_NONE:
				break;
			default:
				break;
			}
			
		}
		catch(Exception e){
			System.err.println("Error while retrieving key in encryption");
			e.printStackTrace();
		}
	}


//	public void decrypt(byte[] key) {
//		
//		// decrypt each section separately
//		try{
//			switch(encryptionMethod){
//			case Encryption_RSA:
//				
//				RSAPrivateKey pk = (RSAPrivateKey)Helper.arrayToPrivateKey(key);
//				algorithms.RSA rsa = new RSA(pk.getModulus());
//				
//				HashMap<String, byte[]> res = new HashMap<String, byte[]>();
//				
//				for(Map.Entry<String, byte[]> ent : map.entrySet()){
//					byte[] enc = rsa.encrypt(new BigInteger(1, ent.getValue()), pk.getPrivateExponent()).toByteArray();
//					res.put(ent.getKey(), enc 
//							);
//					System.out.println(ent.getValue().length + " : " + enc.length);
//					RSA.print(enc);
//				}
//				
//				map = res;
//				
//				break;
//			case Encryption_AES:
//				break;
//			case Encryption_NONE:
//				break;
//			}
//			
//		}
//		catch(Exception e){
//			System.err.println("Error while retrieving key in decryption");
//			e.printStackTrace();
//		}
//	}


	public void validate(byte[] key) throws NotValidMsgException{
		// validate for each in map
		BigInteger newHash;
		try {
			int len = 0;
			for(Map.Entry<String, byte[]> ent : map.entrySet())
				len += ent.getValue().length;

			byte[] res = new byte[len];
			
			int prev = 0;
			for(Map.Entry<String, byte[]> ent : map.entrySet()){
				System.arraycopy(ent.getValue(), 0, res, prev, ent.getValue().length);
				prev += ent.getValue().length;
			}
//			System.out.println("res in validate:");
//			RSA.print(res);
			newHash = new BigInteger(1, SHA256.hash(res));

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		byte[] sign_byte = sign ;
		if(sign_byte != null){
			RSAPublicKey pk = (RSAPublicKey)(Helper.arrayToPublicKey(key));
			algorithms.RSA rsa = new RSA(pk.getModulus());
			BigInteger prevHash = rsa.decrypt(new BigInteger(1,sign_byte), pk.getPublicExponent());
			if(!newHash.equals(prevHash)){
				throw new NotValidMsgException();
			}
		}
	}


	public void setEncryptionMethod(int encryptionMethod) {
		this.encryptionMethod = encryptionMethod ;
	}


	public void put(String key, byte[] value) {
		this.map.put(key, value);
	}
	public byte[] get(String key) throws NotValidMsgException {
		if (this.map.containsKey(key) == false)
			throw new NotValidMsgException() ;
		return this.map.get(key);
	}
		
}
