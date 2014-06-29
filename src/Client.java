

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Scanner;

import common.Msg;
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
		
		while(true){
			String cmd = cin.next() ;
			if (cmd.equals("Exit")){
				break ;
			}else if (cmd.equals("Sign")){
				try
				{
					//-------------------------
					Msg msg = new Msg(client.getPublickKey().getBytes()) ;
					msg.setEncryptionMethod(Msg.Encryption_NONE) ;
					msg.sign(client_private_key) ;
					msg.encrypt(ca_public_key);
					//------------------------- Create & Send MSG
					Socket socket = new Socket(client.caServerName, client.caServerPort);
					OutputStream outToServer = socket.getOutputStream();
					ObjectOutputStream out = new ObjectOutputStream(outToServer);
					out.writeObject(msg);
					//------------------------- Receive MSG & Close
					InputStream inFromServer = socket.getInputStream();
					ObjectInputStream in = new ObjectInputStream(inFromServer);
					Object input = in.readObject() ;
					socket.close();
					//------------------------- 
					Msg ans = (Msg) input ;
					ans.setEncryptionMethod(Msg.Encryption_RSA) ;
					ans.decrypt(client_private_key) ;
					ans.validate(ca_public_key) ; 
					//-------------------------
					client.setCertificate(ans.message); 
				}catch(IOException e){
					e.printStackTrace();
				}catch(NotValidMsgException e){
					//Not Valid Msg 
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				}
			}else if (cmd.equals("Session")){
				try
				{
					//-------------------------
					Msg msg = new Msg(client.cert) ;
					msg.setEncryptionMethod(Msg.Encryption_RSA) ;
					msg.sign(client_private_key) ;
					msg.encrypt(auth_public_key);
					//------------------------- Create & Send MSG
					Socket socket = new Socket(client.authServerName, client.authServerPort);
					OutputStream outToServer = socket.getOutputStream();
					ObjectOutputStream out = new ObjectOutputStream(outToServer);
					out.writeObject(msg);
					//------------------------- Receive MSG & Close
					InputStream inFromServer = socket.getInputStream();
					ObjectInputStream in = new ObjectInputStream(inFromServer);
					Object input = in.readObject() ;
					socket.close();
					//------------------------- 
					Msg ans = (Msg) input ;
					ans.setEncryptionMethod(Msg.Encryption_RSA) ;
					ans.decrypt(client_private_key) ;
					ans.validate(auth_public_key) ; 
					//-------------------------
					client.setSession(ans.message); 
				}catch(IOException e){
					e.printStackTrace();
				}catch(NotValidMsgException e){
					//Not Valid Msg 
					e.printStackTrace();
				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				}
			}else if (cmd.equals("Vote")){
				
			}else{
				System.out.println("Available Commands Are:\n1- Sign\n2- Auth\n3- Vote <name>\n4- Exit");
			}

		}
		cin.close(); 
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
//		return publicKey	 ;
	}
}
