

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;





import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import common.Msg;
import common.NotValidMsgException;


public class Authority extends Thread {
	private ServerSocket serverSocket;
	
	public Authority(String fileName) throws IOException {
		// TODO read conf file
		serverSocket = new ServerSocket(3333);
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
		
		
//		byte[] auth_public_key = null ;
		byte[] auth_private_key = null ;
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
				ans.decrypt(auth_private_key) ;
				ans.validate(client_publick_key) ;
				//-------------------------
				this.validateCert(ans.message) ;
				byte[] session = makeSession(ans.message);
				//-------------------------
				Msg msg = new Msg(session) ;
				msg.setEncryptionMethod(Msg.Encryption_RSA) ;
				msg.sign(auth_private_key) ;
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

	private void validateCert(byte[] cert) throws NotValidMsgException{
		// TODO Auto-generated method stub
		// check for valid certificate 
	}

	private byte[] makeSession(byte[] cert) {
		System.out.println("**recieved: " + new String(cert));
		// TODO Auto-generated method stub
		return "session".getBytes() ;
	}
}



