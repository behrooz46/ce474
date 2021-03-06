package common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.openssl.PEMWriter;

public class Helper {
	public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        ObjectOutputStream o = new ObjectOutputStream(b);
        o.writeObject(obj);
        return b.toByteArray();
    }
	
	public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException{
	    ByteArrayInputStream in = new ByteArrayInputStream(data);
	    ObjectInputStream is = new ObjectInputStream(in);
	    return is.readObject();
	}
	
	public static PublicKey arrayToPublicKey(byte[] key){
		try {
			return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			return null;
		}
	}
	
	public static byte[] keyToArray(Key key){
		return key.getEncoded();
	}
	
	public static PrivateKey arrayToPrivateKey(byte[] key){
		try {
			return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(key));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			return null;
		}
	}
	
	public static PrivateKey loadPrivateKey(String privateFile){
		try{
			File f = new File(privateFile);
		    FileInputStream fis = new FileInputStream(f);
		    DataInputStream dis = new DataInputStream(fis);
		    byte[] keyBytes = new byte[(int)f.length()];
		    dis.readFully(keyBytes);
		    dis.close();
	
		    PKCS8EncodedKeySpec spec =
		      new PKCS8EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePrivate(spec);
		}
		catch(Exception e){
			System.err.println("Error occured while trying to load private key");
			e.printStackTrace();
			return null;
		}
	}
	
	public static PublicKey loadPublicKey(String publicFile){
		try{
			File f = new File(publicFile);
		    FileInputStream fis = new FileInputStream(f);
		    DataInputStream dis = new DataInputStream(fis);
		    byte[] keyBytes = new byte[(int)f.length()];
		    dis.readFully(keyBytes);
		    dis.close();

		    X509EncodedKeySpec spec =
		      new X509EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePublic(spec);
		}
		catch(Exception e){
			System.err.println("Error occured while trying to load public key");
			e.printStackTrace();
			return null;
		}
	}
	
	public static void savePublicKey(PublicKey key, String publicFile){
		try{
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
					key.getEncoded());
			FileOutputStream fos = new FileOutputStream(publicFile);
			fos.write(x509EncodedKeySpec.getEncoded());
			fos.close();
		}
		catch(Exception e){
			System.err.println("Error occured while trying to save public key");
			e.printStackTrace();
		}
	}
	
	public static void savePrivateKey(PrivateKey key, String privateFile){
		try{
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
					key.getEncoded());
			FileOutputStream fos = new FileOutputStream(privateFile);
			fos.write(pkcs8EncodedKeySpec.getEncoded());
			fos.close();
		}
		catch(Exception e){
			System.err.println("Error occured while trying to save private key");
			e.printStackTrace();
		}
	}
	
	public static void printCert(X509Certificate cert){
		System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println("CERTIFICATE TO_STRING");
	    System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println();
	    System.out.println(cert);
	    System.out.println();

	    System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println("CERTIFICATE PEM");
	    System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println();
	    try{
		    PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
		    pemWriter.writeObject(cert);
		    pemWriter.flush();
		    System.out.println();
		    pemWriter.close();
	    }
	    catch(Exception e){
	    	e.printStackTrace();
	    }
	}

	
	public static void main(String[] args) {
		loadPublicKey("Keys/CA/public_key.der");
	}

	public static void printByteArray(byte[] publicKey){
        System.out.println(getStrByteArray(publicKey));
	}
	
	public static String getStrByteArray(byte[] publicKey){
		StringBuffer retString = new StringBuffer();
        for (int i = 0; i < publicKey.length; ++i) {
            retString.append(Integer.toHexString(0x0100 + (publicKey[i] & 0x00FF)).substring(1));
        }
        return retString.toString() ;
	}
}
