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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Random;

import sun.security.provider.SecureRandom;

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
		if (true)
			return ;
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
			body = Helper.serialize(map);
			if (true)
				return ;
			
			switch (encryptionMethod) {
			case Encryption_RSA:
				RSAPublicKey pk = (RSAPublicKey)(Helper.arrayToPublicKey(key));
				  
				algorithms.RSA rsa = new RSA(pk.getModulus());
				
				byte[] ser_map = Helper.serialize(map);
//				RSA.print(ser_map);
				
				int maxByte = (pk.getModulus().bitLength() - 1) / 8;
				
				int sec = maxByte + 3;
				
				
				byte[] len_bytes = ByteBuffer.allocate(4).putInt(ser_map.length).array();
				byte[] len_block = new byte[maxByte];
				System.arraycopy(len_bytes, 0, len_block, maxByte-len_bytes.length, len_bytes.length);
				for(int i = 0 ; i < len_block.length - len_bytes.length ; i++){
					len_block[i] = 0x00;
				}
				
				byte[] final_map = new byte[ser_map.length + len_block.length];
				System.arraycopy(len_block, 0, final_map, 0, len_block.length);
				System.arraycopy(ser_map, 0, final_map, len_block.length, ser_map.length);
				
				
				byte[] res = new byte[(final_map.length / maxByte) * (sec) + 
				                      (final_map.length % maxByte == 0 ? 0 : sec)];
				
				for(int i = 0 ; i < final_map.length/maxByte ; i++){
					byte[] block = new byte[maxByte];
					System.arraycopy(final_map, i * maxByte, block, 0, maxByte);
					BigInteger msg = new BigInteger(1, block);
					BigInteger bodyInteger = rsa.encrypt(msg, pk.getPublicExponent());
					byte[] resBlock = bodyInteger.toByteArray();
					byte[] finalBlock = new byte[sec];
//					System.out.println("result " + resBlock.length);
					if(resBlock.length > maxByte + 1){
						finalBlock[0] = 0x01;
					}
					else{
						finalBlock[0] = 0x00;
						finalBlock[1] = 0x00;
					}
					System.arraycopy(resBlock, 0, finalBlock, finalBlock.length - resBlock.length, resBlock.length);
					System.arraycopy(finalBlock, 0, res, i * (sec), sec);
				}
				
				int rem = final_map.length % maxByte;
				if(rem > 0){
					byte[] block = new byte[maxByte];
					System.arraycopy(final_map, final_map.length - rem, block, 0, rem);
					for(int i = 0 ; i < maxByte - rem ; i++){
						block[rem + i] = 0x00;
					}
					BigInteger msg = new BigInteger(1, block);
					BigInteger bodyInteger = rsa.encrypt(msg, pk.getPublicExponent());
					byte[] resBlock = bodyInteger.toByteArray();
					
//					System.out.println("result " + resBlock.length);
					byte[] finalBlock = new byte[sec];
					
					System.arraycopy(resBlock, 0, finalBlock, finalBlock.length - resBlock.length, resBlock.length);
					if(resBlock.length > maxByte + 1){
						finalBlock[0] = 0x01;
					}
					else{
						finalBlock[0] = 0x00;
						finalBlock[1] = 0x00;
					}
					System.arraycopy(finalBlock, 0, res, res.length - sec, sec);
				}
				
				//decrypt
				
				body = res;
				
//				System.out.println(final_map.length % maxByte);
//				System.out.println(ser_map.length);
				
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


	public void decrypt(byte[] key) {
		
		// decrypt each section separately
		try{
			map = (HashMap<String, byte[]>)(Helper.deserialize(body));
			if (true)
				return ;
			
			switch(encryptionMethod){
			case Encryption_RSA:
				
				RSAPrivateKey pk = (RSAPrivateKey)Helper.arrayToPrivateKey(key);
				algorithms.RSA rsa = new RSA(pk.getModulus());
				
				int maxByte = (pk.getModulus().bitLength() - 1) / 8;
				int sec = maxByte + 3;
				
//				RSA.print(body);
				byte[] res = new byte[(body.length / (sec)) * (maxByte)];
				for(int i = 0 ; i < body.length/(sec) ; i++){
					byte[] block;
					int off = 1;
					if(body[i * sec] == 1){
						block = new byte[sec - 1];
					}
					else{
						block = new byte[sec - 2];
						off = 2;
					}
					System.arraycopy(body, i * (sec) + off, block, 0, sec - off);
					BigInteger msg = new BigInteger(block);
					BigInteger bodyInteger = rsa.decrypt(msg, pk.getPrivateExponent());
					byte[] resBlock = bodyInteger.toByteArray();
					byte[] finalBlock = new byte[maxByte];
					if(resBlock.length <= maxByte){
						System.arraycopy(resBlock, 0, finalBlock, maxByte - resBlock.length, resBlock.length);
						for(int j = 0 ; j < maxByte - resBlock.length ; j++){
							finalBlock[j] = 0x00;
						}
					}
					else{
						System.arraycopy(resBlock, resBlock.length - maxByte, finalBlock, 0, maxByte);
					}
					System.arraycopy(finalBlock, 0 , res, i * (maxByte), maxByte);
				}
				
				
				byte[] res_len = new byte[4];
				System.arraycopy(res, maxByte - 4, res_len, 0, 4);
				ByteBuffer wrapped = ByteBuffer.wrap(res_len); // big-endian by default
				int len = wrapped.getInt();
//				System.out.println(len % maxByte);
//				System.out.println(len);
				byte[] final_res = new byte[len];
				System.arraycopy(res, maxByte, final_res, 0, len);
//				RSA.print(final_res);
				map = (HashMap<String, byte[]>)(Helper.deserialize(final_res));
//				sign = rsa.decrypt(new BigInteger(sign), pk.getPrivateExponent()).toByteArray();
				break;
			case Encryption_AES:
				break;
			case Encryption_NONE:
				break;
			}
			
		}
		catch(Exception e){
			System.err.println("Error while retrieving key in decryption");
			e.printStackTrace();
		}
	}


	public void validate(byte[] key) throws NotValidMsgException{
		if (true)
			return ;
		// validate for each in map
		BigInteger newHash;
		try {
			newHash = new BigInteger(SHA256.hash(Helper.serialize(map)));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		BigInteger prevHash = new BigInteger(sign);
		if(!newHash.equals(prevHash)){
			throw new NotValidMsgException();
		}
		System.out.println("here");
			
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
