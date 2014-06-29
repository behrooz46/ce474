package common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.HashMap;

public class Msg implements Serializable {
	private static final long serialVersionUID = -8154976896133585345L;

	public static final int Encryption_NONE = 0, Encryption_RSA = 1, Encryption_AES = 2 ;
	
	public transient int encryptionMethod;
	
	public int status ; 
	public HashMap<String, byte[]> map ;
	public byte[] sign ;


	public Msg() {
		// TODO Auto-generated constructor stub
		map = new HashMap<String, byte[]>();
	}
	
	
	public void sign(byte[] key) {
		// TODO Auto-generated method stub
		// sign for each in map
	}


	public void encrypt(byte[] key) {
		// TODO Auto-generated method stub
		// encrypt each section separately   
	}


	public void decrypt(byte[] key) {
		// TODO Auto-generated method stub
		// decrypt each section separately
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
}
