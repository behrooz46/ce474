

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.HashMap;
import java.util.Scanner;

import common.Msg;
import common.NetworkErrorException;
import common.NotValidMsgException;


public class Collector extends Thread {

	private ServerSocket serverSocket;
	private boolean finished;
	private int innerIndex;

	HashMap<Integer, byte[]> enc_votes ; 
	
	public Collector(String conf) throws IOException {
		serverSocket = new ServerSocket(4444);
		finished = false ;
		innerIndex = 0 ;
		enc_votes = new HashMap<Integer, byte[]>() ;
	}
	

	public static void main(String[] args) {
		try
		{
			Collector co = new Collector("conf.txt") ;
			co.start();
			
			Scanner cin = new Scanner(System.in);
			while(true){
				String cmd = cin.next() ;
				if ( cmd.equals("end") ){
					try {
						co.finish();
						break ;
					} catch (NetworkErrorException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NotValidMsgException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
			}
		}catch(IOException e)
		{
			e.printStackTrace();
		}

	}

	private void finish() throws NetworkErrorException, NotValidMsgException {
		
		//---------------
		Msg msg = new Msg(), ans = null ;
		msg.put("request", null);
		
		msg.setEncryptionMethod(Msg.Encryption_NONE) ;
		msg.sign(null) ;
		msg.encrypt(null);
		//------------------------- 
		try {
			Socket socket = new Socket("localhost", 3333);
			OutputStream outToServer = socket.getOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(outToServer);
			out.writeObject(msg);
			//------------------------- 
			InputStream inFromServer = socket.getInputStream();
			ObjectInputStream in = new ObjectInputStream(inFromServer);
			Object input = in.readObject() ;
			//TODO read hash map 
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
		ans.validate(null) ;
		ans.setEncryptionMethod(Msg.Encryption_RSA) ;
		ans.decrypt(null) ;
		//TODO read message
		
		finished = true ;
	}


	@Override
	public void run() {
		while(!finished)
		{
			try
			{
				Socket server = serverSocket.accept();
				if (finished){
					server.close(); 
					break; 
				}

				ObjectInputStream in = new ObjectInputStream(server.getInputStream());
				Object input = in.readObject() ;
				//-------------------------
				Msg ans = (Msg) input ;
				ans.setEncryptionMethod(Msg.Encryption_RSA) ;
				ans.decrypt(null) ;
				ans.validate(null) ;
				//-------------------------
				byte[] index = getIndex(ans.get("inner")) ;
				//-------------------------
				Msg msg = new Msg() ;
				msg.put("index", index);
				msg.setEncryptionMethod(Msg.Encryption_RSA) ;
				msg.sign(null) ;
				msg.encrypt(null);
				//-------------------------
				ObjectOutputStream out = new ObjectOutputStream(server.getOutputStream());
				out.writeObject(msg);
				
				server.close();
			}catch(SocketTimeoutException s)
			{
				System.out.println("Socket timed out!");
				break;
			}catch(IOException e)
			{
				e.printStackTrace();
				break;
			} catch (NotValidMsgException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	private byte[] getIndex(byte[] vote) {
		enc_votes.put(new Integer(innerIndex), vote);
		String ret = "" + innerIndex ;
		innerIndex ++ ;
		return ret.getBytes();
	}
}
