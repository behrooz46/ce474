

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Scanner;

import common.Helper;
import common.Msg;
import common.NetworkErrorException;
import common.NotValidMsgException;

public class Client {
	private static final String id = "1";
	byte[] cert;
	private String publicKey;
	
	private String caServerName;
	private int caServerPort;
	private String collectServerName;
	private int collectServerPort;
	private String authServerName;
	private int authServerPort;
	private byte[] session;
	private byte[] index;

	public Client(String fileName) throws IOException {
		// TODO read conf file
		caServerName = "localhost";
		caServerPort = 2222;
		authServerName = "localhost";
		authServerPort = 3333;
		collectServerName = "localhost";
		collectServerPort = 4444;
		//----------------------- read public key
//		BufferedReader reader = new BufferedReader(new FileReader("src/client/"+ this.id +"/publickey.pem"));
//		String line = null ; publicKey = "" ;
//		while ((line = reader.readLine()) != null) {
//			publicKey += line ;
//			publicKey += "\n" ;
//		}
//		reader.close();
	}

	public static void main(String[] args) throws IOException {
		
		Scanner cin = new Scanner(System.in);
		Client client = new Client("conf.txt") ;
		
		byte[] ca_public_key = null ;
		byte[] auth_public_key = null ;
		byte[] client_private_key = null ;
//		byte[] client_publick_key = null ;
		String name = cin.next() ;
		while(true){
			String cmd = cin.next() ;
			try
			{
				
				if (cmd.equals("Exit")){
					break ;
				}else if (cmd.equals("Sign")){
					//-------------------------
					Msg msg = new Msg() ;
					msg.put("public", client.getPublickKey().getBytes());
					msg.put("name", name.getBytes());
					
					msg.setEncryptionMethod(Msg.Encryption_NONE) ;
					msg.sign(client_private_key) ;
					msg.encrypt(ca_public_key);
					//-------------------------
					Msg ans = client.communicate(client.caServerName, client.caServerPort, msg) ;
					ans.setEncryptionMethod(Msg.Encryption_RSA) ;
					ans.decrypt(client_private_key) ;
					ans.validate(ca_public_key) ; 
					//-------------------------
					client.setCertificate(ans.get("cert")); 
				}else if (cmd.equals("Session")){
					//-------------------------
					Msg msg = new Msg() ;
					msg.status = 800 ;
					msg.put("cert", client.cert);
					msg.setEncryptionMethod(Msg.Encryption_RSA) ;
					msg.sign(client_private_key) ;
					msg.encrypt(auth_public_key);
					//-------------------------
					Msg ans = client.communicate(client.authServerName, client.authServerPort, msg) ;
					ans.setEncryptionMethod(Msg.Encryption_RSA) ;
					ans.decrypt(client_private_key) ;
					ans.validate(auth_public_key) ; 
					//-------------------------
					client.setSession(ans.get("session")); 
				}else if (cmd.equals("Vote")){
					String vote = cin.next() ;
					//-------------------------
					Msg msg = new Msg() ;
					msg.put("vote", vote.getBytes());
					msg.setEncryptionMethod(Msg.Encryption_RSA) ;
					msg.sign(client_private_key) ;
					msg.encrypt(auth_public_key);
					//-------------------------
					Msg ans = client.communicate(client.collectServerName, client.collectServerPort, msg) ;
					ans.setEncryptionMethod(Msg.Encryption_RSA) ;
					ans.decrypt(client_private_key) ;
					ans.validate(auth_public_key) ; 
					//-------------------------
					client.setIndex(ans.get("index"));
					//-------------------------
					Msg innerMsg = new Msg() ;
					innerMsg.put("cert", client.cert);
					innerMsg.put("index", client.index);
					innerMsg.setEncryptionMethod(Msg.Encryption_AES) ;
					innerMsg.encrypt(client.session);
					//=============
					msg = new Msg() ;
					msg.status = 801 ; 
					msg.put("cert", client.cert);
					msg.put("inner", Helper.serialize(innerMsg));
					msg.setEncryptionMethod(Msg.Encryption_RSA) ;
					msg.sign(client_private_key) ;
					msg.encrypt(auth_public_key);
					//-------------------------
					client.communicate(client.authServerName, client.authServerPort, msg) ;
				}else{
					System.out.println("Available Commands Are:\n1- Sign\n2- Auth\n3- Vote <name>\n4- Exit");
				}
			}catch(NotValidMsgException e){
				//TODO Not Valid Msg 
				e.printStackTrace();
			} catch (NetworkErrorException e) {
				//TODO Network Error
				e.printStackTrace();
			}
		}
		cin.close(); 
	}

	private void setFinished(byte[] message) {
		// TODO Auto-generated method stub
		
	}

	private void setIndex(byte[] message) {
		this.index = message ;
		
	}

	private void setSession(byte[] session) {
		System.out.println("**recieved: " + new String(session));
		this.session = session ;
	}

	private void setCertificate(byte[] cert) {
		System.out.println("**recieved: " + new String(cert));
		this.cert = cert ;
	}

	private String getPublickKey(){
		return "PublicKey";
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
}
