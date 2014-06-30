

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import ca.SignServer;
import common.Helper;
import common.Msg;
import common.NotValidMsgException;


public class CA extends Thread{
	private ServerSocket serverSocket;
	 
	private byte[] publicKey, privateKey;
	
	private String serverName, collectServerName, authServerName;
	private int serverPort, collectServerPort, authServerPort;
	private byte[] collectPublicKey, authPublicKey;

	private X509Certificate cert;

	private SignServer signServer;
	
	public CA(String conf) throws IOException {
		// TODO read conf file
		serverSocket = new ServerSocket(2222);
		Scanner cin = new Scanner(new File(conf) );
		//--------------
		serverName = cin.next() ; serverPort = cin.nextInt() ;
		String publicFile = cin.next() ;
		String privateFile = "Keys/CA/private_key.der" ;
		
		//--------------
		authServerName = cin.next() ; authServerPort = cin.nextInt() ;
		authPublicKey = Helper.loadPublicKey(cin.next()).getEncoded() ;
		collectServerName = cin.next() ; collectServerPort = cin.nextInt() ;
		collectPublicKey = Helper.loadPublicKey(cin.next()).getEncoded() ;
		cin.close();
		//--------------
		publicKey = Helper.loadPublicKey(publicFile).getEncoded() ;
		privateKey = Helper.loadPrivateKey(privateFile).getEncoded() ;
		
		this.signServer = new SignServer(publicFile, privateFile) ;
		this.cert = signServer.generateSelfSignedX509Certificate() ;
	}

	public static void main(String[] args) {
		try
		{
			CA ca = new CA("conf.txt") ;
			ca.start();
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
				ans.setEncryptionMethod(Msg.Encryption_RSA) ;
				ans.decrypt(privateKey) ;
//				ans.validate(null) ;
				//-------------------------		
				byte[] pu = ans.get("public") ;
				byte[] name = ans.get("name") ;
				byte[] cert = makeCertificate(pu, new String(name));
				//-------------------------
				Msg msg = new Msg() ;
				msg.put("cert", cert);
				msg.setEncryptionMethod(Msg.Encryption_RSA) ;
				msg.sign(this.privateKey) ;
				msg.encrypt(pu);
				//-------------------------
				ObjectOutputStream out = new ObjectOutputStream(server.getOutputStream());
				out.writeObject(msg);
				server.close();
			}catch(IOException e){
				e.printStackTrace();
			}catch(NotValidMsgException e){
				//Not Valid Msg 
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	private byte[] makeCertificate(byte[] pu, String name) throws IOException {
		PublicKey PU = Helper.arrayToPublicKey(pu);
		X509Certificate ret = signServer.createCert(PU, name) ;
		return Helper.serialize(ret); 
	}
}


