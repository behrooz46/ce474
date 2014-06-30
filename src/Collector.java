import java.io.File;
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

import common.Helper;
import common.KeyType;
import common.Msg;
import common.NetworkErrorException;
import common.NotValidMsgException;


public class Collector extends Thread {

	private ServerSocket serverSocket;
	private Boolean finished;
	private int innerIndex;

	HashMap<Integer, byte[]> enc_votes ;
	
	private byte[] publicKey, privateKey;
	
	private String serverName, authServerName, caServerName;
	private int serverPort, authServerPort, caServerPort;
	private byte[] authPublicKey, caPublicKey;
	
	public Collector(String conf) throws IOException {
		finished = false ;
		innerIndex = 0 ;
		enc_votes = new HashMap<Integer, byte[]>() ;
		
		Scanner cin = new Scanner(new File(conf) );
		//--------------
		caServerName = cin.next() ; caServerPort = cin.nextInt() ;
		caPublicKey = Helper.loadPublicKey(cin.next()).getEncoded() ;
		authServerName = cin.next() ; authServerPort = cin.nextInt() ;
		authPublicKey = Helper.loadPublicKey(cin.next()).getEncoded() ;
		serverName = cin.next() ; serverPort = cin.nextInt() ;
		String publicFile = cin.next() ;
		String privateFile = "Keys/Collector/private_key.der" ;
		serverSocket = new ServerSocket(serverPort);
		cin.close();
		//--------------
		publicKey = Helper.loadPublicKey(publicFile).getEncoded() ;
		privateKey = Helper.loadPrivateKey(privateFile).getEncoded() ;
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
			cin.close();
		}catch(IOException e)
		{
			e.printStackTrace();
		}

	}

	private void finish() throws NetworkErrorException, NotValidMsgException {
		synchronized (finished) {
			finished = true ;	
		}
		//---------------
		Msg msg = new Msg(), ans = null ;
		msg.put("request", null);
		
		msg.setEncryptionMethod(Msg.Encryption_NONE) ;
		msg.status = 700 ;
		msg.sign(null) ;
		msg.encrypt(null, KeyType.SYM);
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
			socket.close();
			//-------------------------
			ans = (Msg) input ;
			ans.setEncryptionMethod(Msg.Encryption_RSA) ;
			ans.encrypt(null, KeyType.SYM) ;
			ans.validate(null) ;
			HashMap<Integer, byte[]> map = (HashMap<Integer, byte[]>) Helper.deserialize( ans.get("map") );
			process(map);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new NetworkErrorException() ;
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new NetworkErrorException() ;
		}
	}


	private void process(HashMap<Integer, byte[]> map) {
		for (Integer index : map.keySet()) {
			try {
				System.out.println(index);
				
				byte[] session = map.get(index);
				Msg msg = (Msg) Helper.deserialize(enc_votes.get(index)) ;
				
				msg.setEncryptionMethod(Msg.Encryption_AES);
				msg.encrypt(session, KeyType.SYM);
				String vote = new String(msg.get("vote"));
				
				System.out.println(index + " " + vote) ;
			} catch (NotValidMsgException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
 		}
	}


	@Override
	public void run() {
		while(true)
		{
			synchronized (finished) {
				if (finished){
					break; 
				}	
			}
			
			try
			{
				Socket server = serverSocket.accept();
				synchronized (finished) {
					if (finished){
						server.close(); 
						break; 
					}	
				}
				

				ObjectInputStream in = new ObjectInputStream(server.getInputStream());
				Object input = in.readObject() ;
				//-------------------------
				Msg ans = (Msg) input ;
				ans.setEncryptionMethod(Msg.Encryption_NONE) ;
				ans.encrypt(null, KeyType.SYM) ;
				ans.validate(null) ;
				//-------------------------
				byte[] index = getIndex(ans.get("vote")) ;
				//-------------------------
				Msg msg = new Msg() ;
				msg.put("index", index);
				msg.setEncryptionMethod(Msg.Encryption_NONE) ;
				msg.sign(privateKey) ;
				msg.encrypt(null, KeyType.SYM);
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
		try {
			Msg inner = (Msg) Helper.deserialize(vote);
			inner.setEncryptionMethod(Msg.Encryption_AES);
			inner.encrypt(null, KeyType.SYM);
			System.out.println("Vote: " + new String(inner.get("vote")));
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NotValidMsgException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		enc_votes.put(new Integer(innerIndex), vote);
		String ret = "" + innerIndex ;
		innerIndex ++ ;
		return ret.getBytes();
	}
}
