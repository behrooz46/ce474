package common;

import java.io.Serializable;

public class Msg implements Serializable {
	private static final long serialVersionUID = -8154976896133585345L;

	public static final int Encryption_NONE = 0, Encryption_RSA = 1, Encryption_AES = 2 ;
	
	public transient int encryptionMethod;
	
	public int status ;
	public byte[] message ;
	public byte[] aux ;
	public byte[] sign ;


	public Msg(byte[] bytes) {
		// TODO Auto-generated constructor stub
		this.message = bytes ;
	}
	
	
	public void sign(byte[] key) {
		// TODO Auto-generated method stub
		// sign status + message + aux
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
		// validate status + message + aux
	}


	public void setEncryptionMethod(int encryptionMethod) {
		this.encryptionMethod = encryptionMethod ;
	}
}
