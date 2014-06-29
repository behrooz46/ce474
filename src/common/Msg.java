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
			RSAPrivateKey pk = (RSAPrivateKey)SignServer.arrayToPrivateKey(key);
			algorithms.RSA rsa = new algorithms.RSA(pk.getModulus());
			BigInteger msg = new BigInteger(SHA256.hash(serialize(map)));
			sign = rsa.encrypt(msg, pk.getPrivateExponent()).toByteArray();
		}
		catch(Exception e){
			System.err.println("Error while retrieving key in sigining");
		}
	}


	public void encrypt(byte[] key) {
		// encrypt each section separately
		try{
			RSAPublicKey pk = (RSAPublicKey)SignServer.arrayToPublicKey(key);
			algorithms.RSA rsa = new RSA(pk.getModulus());
			BigInteger msg = new BigInteger(serialize(map));
			body = rsa.encrypt(msg, pk.getPublicExponent()).toByteArray();
		}
		catch(Exception e){
			System.err.println("Error while retrieving key in encryption");
		}
	}


	public void decrypt(byte[] key) {
		// decrypt each section separately
		try{
			RSAPrivateKey pk = (RSAPrivateKey)SignServer.arrayToPrivateKey(key);
			algorithms.RSA rsa = new RSA(pk.getModulus());
			BigInteger msg = new BigInteger(body);
			body = rsa.encrypt(msg, pk.getPrivateExponent()).toByteArray();
			map = (HashMap<String, byte[]>)deserialize(body);
			
		}
		catch(Exception e){
			System.err.println("Error while retrieving key in decryption");
		}
	}


	public void validate(byte[] key) throws NotValidMsgException{
		// TODO Auto-generated method stub
		// validate for each in map
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
	
	public static byte[] getByteArray(Msg msg) throws IOException{
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		ObjectOutput out = new ObjectOutputStream(bos);   
		out.writeObject(msg);
		byte[] innerByte = bos.toByteArray();
		out.close();
		bos.close();
		return innerByte ;
	}
	
	public static Msg getMsg(byte[] inner) throws IOException, ClassNotFoundException{
		ByteArrayInputStream bis = new ByteArrayInputStream(inner);
		ObjectInput oin = new ObjectInputStream(bis);
		return (Msg) oin.readObject();
	}
	
	private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream o = new ObjectOutputStream(b);
        o.writeObject(obj);
        return b.toByteArray();
    }
	
	private Object deserialize(byte[] data) throws IOException, ClassNotFoundException{
	    ByteArrayInputStream in = new ByteArrayInputStream(data);
	    ObjectInputStream is = new ObjectInputStream(in);
	    return is.readObject();
	}
}
