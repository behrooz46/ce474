import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import common.Helper;
import common.KeyType;
import common.Msg;
import common.NetworkErrorException;
import common.NotValidMsgException;

public class Client {
	private static final String id = "1";
	byte[] cert;
	
	private byte[] publicKey, privateKey;
	
	private String caServerName, collectServerName, authServerName;
	private int caServerPort, collectServerPort, authServerPort;
	private byte[] caPublicKey, collectPublicKey, authPublicKey;
	
	private byte[] session;
	private byte[] index;
	public String name;
	
	private byte[] caPrivateKey;
	

	public Client(String conf, String name) throws IOException, NoSuchAlgorithmException {
		this.name = name;
		//-----------------------
		Scanner cin = new Scanner(new File(conf) );
		caServerName = cin.next() ; caServerPort = cin.nextInt() ;
		caPublicKey = Helper.loadPublicKey(cin.next()).getEncoded() ;
		authServerName = cin.next() ; authServerPort = cin.nextInt() ;
		authPublicKey = Helper.loadPublicKey(cin.next()).getEncoded() ;
		collectServerName = cin.next() ; collectServerPort = cin.nextInt() ;
		collectPublicKey = Helper.loadPublicKey(cin.next()).getEncoded() ;
		cin.close();
		//----------------------- read public key
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        this.publicKey  =  keyGen.genKeyPair().getPublic().getEncoded();
        this.privateKey = keyGen.genKeyPair().getPrivate().getEncoded();
        
	}

	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		
		Scanner cin = new Scanner(System.in);
		Client client = new Client("conf.txt", "Behrooz") ;
		
		while(true){
			String cmd = cin.next() ;
			try
			{
				if (cmd.equals("Exit")){
					break ;
				}else if (cmd.equals("Sign")){
					signWithCA(client) ;
				}else if (cmd.equals("Auth")){
					authWithAuth(client);
				}else if (cmd.equals("Vote")){
					String vote = cin.next() ;
					voteWithCollector(client, vote);
				}else{
					System.out.println("Available Commands Are:\n1- Sign\n2- Auth\n3- Vote <name>\n4- Exit");
				}
			}catch(NotValidMsgException e){
				//TODO Not Valid Msg 
				e.printStackTrace();
			} catch (NetworkErrorException e) {
				//TODO Network Error
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		cin.close(); 
	}

	private void setIndex(byte[] index) {
		this.index = index ;
		System.out.println(new String(index));
	}

	private void setSession(byte[] session) {
		Helper.printByteArray(session);
		this.session = session ;
	}

	private void setCertificate(byte[] cert) throws ClassNotFoundException, IOException {
		X509Certificate ret = (X509Certificate) Helper.deserialize(cert) ;
//		Helper.printCert(ret);
		System.out.println("Certificate Recieved but not printed :D");
		this.cert = cert ;
	}

	private Msg communicate(String server, int port, Msg msg) throws NetworkErrorException {
		Msg ans = null ; 
		//------------------------- 
		try {
			Socket socket = new Socket(server, port);
			OutputStream outToServer = socket.getOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(outToServer);
			out.writeObject(msg);
			//------------------------- 
			InputStream inFromServer = socket.getInputStream();
			ObjectInputStream in = new ObjectInputStream(inFromServer);
			Object input = in.readObject() ;
			
			socket.close();
			ans = (Msg) input ;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new NetworkErrorException() ;
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new NetworkErrorException() ;
		}
		//------------------------- 
		return ans;
	}
	
	
	
	
	

	private static void voteWithCollector(Client client, String vote) throws NetworkErrorException, NotValidMsgException, IOException {
		//-------------------------
		Msg msg = new Msg() ;
		Msg innerMsg = new Msg() ;
		
		innerMsg.put("vote", vote.getBytes());
		innerMsg.setEncryptionMethod(Msg.Encryption_AES) ;
		innerMsg.encrypt(client.session, KeyType.SYM);

		msg.put("inner", Helper.serialize(innerMsg));
		
		msg.setEncryptionMethod(Msg.Encryption_RSA) ;
		msg.sign(client.privateKey) ;
		msg.encrypt(null, KeyType.SYM);
		//-------------------------
		Msg ans = client.communicate(client.collectServerName, client.collectServerPort, msg) ;
		ans.setEncryptionMethod(Msg.Encryption_RSA) ;
		ans.encrypt(client.privateKey, KeyType.Private) ;
		ans.validate(null) ; 
		//-------------------------
		client.setIndex(ans.get("index"));
		//-------------------------
		innerMsg = new Msg() ;
		innerMsg.put("cert", client.cert);
		innerMsg.put("index", client.index);
		innerMsg.setEncryptionMethod(Msg.Encryption_AES) ;
		innerMsg.encrypt(client.session, KeyType.SYM);
		//=============
		msg = new Msg() ;
		msg.status = 801 ; 
		msg.put("cert", client.cert);
		msg.put("inner", Helper.serialize(innerMsg));
		msg.setEncryptionMethod(Msg.Encryption_RSA) ;
		msg.sign(client.privateKey) ;
		msg.encrypt(null, KeyType.SYM);
		//-------------------------
		client.communicate(client.authServerName, client.authServerPort, msg) ;
		
	}

	private static void authWithAuth(Client client) throws NetworkErrorException, NotValidMsgException {
		//-------------------------
		Msg msg = new Msg() ;
		msg.status = 800 ;
		msg.put("cert", client.cert);
		msg.setEncryptionMethod(Msg.Encryption_NONE) ;
		msg.sign(null) ;
		msg.encrypt(client.authPublicKey, KeyType.Public);
		//-------------------------
		Msg ans = client.communicate(client.authServerName, client.authServerPort, msg) ;
		ans.setEncryptionMethod(Msg.Encryption_RSA) ;
		ans.encrypt(client.privateKey, KeyType.Private) ;
		ans.validate(client.authPublicKey) ; 
		//-------------------------
		client.setSession(ans.get("session")); 
	}

	private static void signWithCA(Client client) throws NetworkErrorException, NotValidMsgException, ClassNotFoundException, IOException {
		//-------------------------
		Msg msg = new Msg() ;
		msg.put("public", client.publicKey);
		msg.put("name", client.name.getBytes());
		
		msg.setEncryptionMethod(Msg.Encryption_NONE) ;
		msg.sign(null) ;
		msg.encrypt(client.caPublicKey, KeyType.Public);
		//-------------------------
		Msg ans = client.communicate(client.caServerName, client.caServerPort, msg) ;
		ans.setEncryptionMethod(Msg.Encryption_NONE) ;
		ans.encrypt(client.privateKey, KeyType.Private) ;
		ans.validate(client.caPublicKey) ; 
//		-------------------------
		client.setCertificate(ans.get("cert")); 
	}

}
