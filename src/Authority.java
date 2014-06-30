

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Scanner;

import ca.SignServer;

import common.Helper;
import common.KeyType;
import common.Msg;
import common.NotValidMsgException;


public class Authority extends Thread {
	private ServerSocket serverSocket;
	public boolean finished;
	
	private HashMap<String, byte[]> c2cert ;
	private HashMap<String, byte[]> c2session ;
	private HashMap<String, byte[]> c2index ;
	
	
	private byte[] publicKey, privateKey;
	
	private String serverName, collectServerName, caServerName;
	private int serverPort, collectServerPort, caServerPort;
	private byte[] collectPublicKey, caPublicKey;
	
	public Authority(String conf) throws IOException {
		// TODO read conf file
		
		c2cert    = new HashMap<String, byte[]>() ;
		c2session = new HashMap<String, byte[]>() ;
		c2index   = new HashMap<String, byte[]>() ;
		
		Scanner cin = new Scanner(new File(conf) );
		//--------------
		caServerName = cin.next() ; caServerPort = cin.nextInt() ;
		caPublicKey = Helper.loadPublicKey(cin.next()).getEncoded() ;
		//--------------
		serverName = cin.next() ; serverPort = cin.nextInt() ;
		String publicFile = cin.next() ;
		String privateFile = "Keys/Auth/private_key.der" ;
		serverSocket = new ServerSocket(serverPort);
		//--------------
		collectServerName = cin.next() ; collectServerPort = cin.nextInt() ;
		collectPublicKey = Helper.loadPublicKey(cin.next()).getEncoded() ;
		cin.close();
		//--------------
		publicKey = Helper.loadPublicKey(publicFile).getEncoded() ;
		privateKey = Helper.loadPrivateKey(privateFile).getEncoded() ;
	}

	public static void main(String[] args) {
		try
		{
			Authority au = new Authority("conf.txt") ;
			au.start();
		}catch(IOException e)
		{
			e.printStackTrace();
		}

	}
	
	@Override
	public void run() {
		while(true)
		{
			try
			{
				Socket server = serverSocket.accept();
				ObjectInputStream in = new ObjectInputStream(server.getInputStream());
				Object input = in.readObject() ;
				//-------------------------
				Msg ans = (Msg) input ;
				
				//-------------------------
				if (ans.status == 700){
					ans.setEncryptionMethod(Msg.Encryption_NONE) ;
					ans.encrypt(privateKey, KeyType.Private) ;
					ans.validate(collectPublicKey) ;
					
					Msg msg = new Msg() ;
					msg.put("map", getSIndex());
					
					msg.setEncryptionMethod(Msg.Encryption_RSA) ;
					msg.sign(null);
					msg.encrypt(null, KeyType.SYM); 
					
					
					ObjectOutputStream out = new ObjectOutputStream(server.getOutputStream());
					out.writeObject(msg);
				}else{
					ans.setEncryptionMethod(Msg.Encryption_NONE) ;
					ans.encrypt(privateKey, KeyType.Private) ;
					ans.validate(null) ;
					
					byte[] cert = ans.get("cert") ;
					X509Certificate realCert = this.validateCert(cert) ;
					PublicKey PU = realCert.getPublicKey();
					byte[] client_pu = PU.getEncoded() ;
					
					if (ans.status == 800){
						byte[] session = makeSession(cert);
						//-------------------------
						Msg msg = new Msg() ;
						msg.put("session", session);
						msg.setEncryptionMethod(Msg.Encryption_RSA) ;
						msg.sign(privateKey) ;
						msg.encrypt(client_pu, KeyType.Public);
						//-------------------------
						ObjectOutputStream out = new ObjectOutputStream(server.getOutputStream());
						out.writeObject(msg);
					}else if (ans.status == 801){
						byte[] session = this.getSessionKey(cert);
						byte[] tmpByte = ans.get("inner");
						//-------------------------
						Msg inner = (Msg)(Helper.deserialize(tmpByte));
						inner.setEncryptionMethod(Msg.Encryption_AES) ;
						inner.encrypt(session, KeyType.SYM);
						byte[] cert2 = inner.get("cert");
						byte[] index = inner.get("index");
						//-------------------------
						if ( Arrays.equals(cert, cert2) == false )
							throw new NotValidMsgException() ;
						this.addVote(cert, session, index);
						//-------------------------
						Msg msg = new Msg() ;
						ObjectOutputStream out = new ObjectOutputStream(server.getOutputStream());
						out.writeObject(msg);
					}
				}
				server.close();
			}catch(IOException e){
				e.printStackTrace();
			}catch(NotValidMsgException e){
				//Not Valid Msg 
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (CertificateException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchProviderException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (SignatureException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	private byte[] getSIndex() throws IOException {
		HashMap<Integer, byte[]> map = new HashMap<Integer, byte[]> () ;
		c2cert.put("a", null);
		c2session.put("a", "salam".getBytes());
		c2index.put("a", "0".getBytes());
		
		for (String id : c2cert.keySet()) {
			Integer index = new Integer(new String(c2index.get(id))); 
			map.put(index, c2session.get(id)) ;
			System.out.println("PRIININININIT.... " + index + " " + new String(c2session.get(id)) );
		}
		return Helper.serialize(map) ;
	}

	private void addVote(byte[] cert, byte[] session, byte[] index) throws NotValidMsgException {
		String id = Helper.getStrByteArray(cert) ;
		
		if ( c2session.containsKey(id) == false )
			throw new NotValidMsgException() ;
		if ( Arrays.equals(c2session.get(id) , session)  == false  )
			throw new NotValidMsgException() ;
		if (   c2index.containsKey(id) == true )
			throw new NotValidMsgException() ;
		
		System.out.println("Vote added : " + Helper.getStrByteArray(session) + "\n"+ new String(index));
		c2index.put(id, index);  
	}

	private byte[] getSessionKey(byte[] cert) throws NotValidMsgException {
		String id = Helper.getStrByteArray(cert) ;
		
		if ( c2session.containsKey(id) == false )
			throw new NotValidMsgException() ;
		return c2session.get(id) ;
	}

	private X509Certificate validateCert(byte[] cert) throws ClassNotFoundException, IOException, InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{
		X509Certificate ret = (X509Certificate) Helper.deserialize(cert) ;
		PublicKey ca = Helper.arrayToPublicKey(caPublicKey);
		ret.checkValidity();
		SignServer.verify(ret, ca) ;
		return ret ; 
	}

	private byte[] makeSession(byte[] cert) throws NotValidMsgException {
		String id = Helper.getStrByteArray(cert) ;
		
		if ( c2session.containsKey(id) == true )
			throw new NotValidMsgException() ;

		SecureRandom sr = new SecureRandom();

		byte[] session = new byte[32];
//		byte[] iv = new byte[16];
		sr.nextBytes(session);
		Helper.printByteArray(session);
//		sr.nextBytes(iv);
		c2cert.put(id, cert);
		c2session.put(id, session);
		return session;
	}
}



