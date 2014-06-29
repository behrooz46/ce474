

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import common.Msg;
import common.NotValidMsgException;


public class CA extends Thread{
	private ServerSocket serverSocket;
	
	public CA(String fileName) throws IOException {
		// TODO read conf file
		serverSocket = new ServerSocket(2222);
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
		
		
//		byte[] ca_public_key = null ;
		byte[] ca_private_key = null ;
//		byte[] client_private_key = null ;
		byte[] client_publick_key = null ;
		
		
		while(true)
		{
			try
			{
				Socket server = serverSocket.accept();
				ObjectInputStream in = new ObjectInputStream(server.getInputStream());
				Object input = in.readObject() ;
				//-------------------------
				Msg ans = (Msg) input ;
				ans.setEncryptionMethod(Msg.Encryption_NONE) ;
				ans.decrypt(ca_private_key) ;
				ans.validate(client_publick_key) ;
				//-------------------------				
				byte[] cert = makeCertificate(ans.message);
				//-------------------------
				Msg msg = new Msg(cert) ;
				msg.setEncryptionMethod(Msg.Encryption_RSA) ;
				msg.sign(ca_private_key) ;
				msg.encrypt(client_publick_key);
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

	private byte[] makeCertificate(byte[] message) {
		System.out.println("**recieved: " + new String(message));
		// TODO Auto-generated method stub
		return "cert".getBytes() ;
	}
}


