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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

import ca.SignServer;
import algorithms.*;

public class Msg implements Serializable {
	private static final long serialVersionUID = -8154976896133585345L;

	public static final int Encryption_NONE = 0, Encryption_RSA = 1, Encryption_AES = 2 ;
	
	public transient int encryptionMethod;
	
	public int status ; 
	transient public HashMap<String, byte[]> map ;
	public byte[] body;
	public byte[] sign ;


	public Msg() {
		// TODO Auto-generated constructor stub
		map = new HashMap<String, byte[]>();
	}
	
	
	public void sign(byte[] key) {
		// sign for each in map
		try{
			RSAPrivateKey pk = (RSAPrivateKey)Helper.arrayToPrivateKey(key);
			algorithms.RSA rsa = new algorithms.RSA(pk.getModulus());
			BigInteger msg = new BigInteger(SHA256.hash(Helper.serialize(map)));
			sign = rsa.encrypt(msg, pk.getPrivateExponent()).toByteArray();
		}
		catch(Exception e){
			System.err.println("Error while sigining");
		}
	}


	public void encrypt(byte[] key) {
		// encrypt each section separately
		try{
			RSAPublicKey pk = (RSAPublicKey)Helper.arrayToPublicKey(key);
			algorithms.RSA rsa = new RSA(pk.getModulus());
//			BigInteger msg = new BigInteger(Helper.serialize(map));
//			body = rsa.encrypt(msg, pk.getPublicExponent()).toByteArray();
			body = Helper.serialize(map);
		}
		catch(Exception e){
			System.err.println("Error while retrieving key in encryption");
		}
	}


	public void decrypt(byte[] key) {
		// decrypt each section separately
		try{
			RSAPrivateKey pk = (RSAPrivateKey)Helper.arrayToPrivateKey(key);
			algorithms.RSA rsa = new RSA(pk.getModulus());
//			BigInteger msg = new BigInteger(body);
//			body = rsa.encrypt(msg, pk.getPrivateExponent()).toByteArray();
			map = (HashMap<String, byte[]>)(Helper.deserialize(body));
//			sign = rsa.decrypt(new BigInteger(sign), pk.getPrivateExponent()).toByteArray();
			
		}
		catch(Exception e){
			System.err.println("Error while retrieving key in decryption");
			e.printStackTrace();
		}
	}


	public void validate(byte[] key) throws NotValidMsgException{
		// validate for each in map
		try {
			BigInteger newHash = new BigInteger(SHA256.hash(Helper.serialize(map)));
			BigInteger prevHash = new BigInteger(sign);
			if(!newHash.equals(prevHash)){
				throw new NotValidMsgException();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
