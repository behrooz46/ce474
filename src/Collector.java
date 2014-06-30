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
	HashMap<String, Integer> answers ; 
	
	
	private byte[] publicKey, privateKey;
	
	private String serverName, authServerName, caServerName;
	private int serverPort, authServerPort, caServerPort;
	private byte[] authPublicKey, caPublicKey;
	private Integer max_vote_cnt;
	private String max_vote;
	
	public Collector(String conf) throws IOException {
		finished = false ;
		innerIndex = 0 ;
		enc_votes = new HashMap<Integer, byte[]>() ;
		answers = new HashMap<String, Integer>() ;
		
		max_vote_cnt = -1; 
		max_vote = "No Vote" ;
		
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
//						e.printStackTrace();
					} catch (NotValidMsgException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
			}
			cin.close();
		}catch(IOException e)
		{
//			e.printStackTrace();
		}

	}

	private void finish() throws NetworkErrorException, NotValidMsgException {
		synchronized (finished) {
			finished = true ;	
		}
		//------------------------- 
		try {
			HashMap<Integer, byte[]> map = new HashMap<Integer, byte[]>() ;
			
			for(Integer index : enc_votes.keySet()){
//				System.err.println("getting for index: " + index);
				Socket socket = new Socket("localhost", 3333);
				OutputStream outToServer = socket.getOutputStream();
				ObjectOutputStream out = new ObjectOutputStream(outToServer);
				
				
				Msg msg = new Msg(), ans = null ;
				msg.put("index", new String(index + "").getBytes());
				
				msg.setEncryptionMethod(Msg.Encryption_RSA) ;
				msg.status = 700 ;
				msg.sign(privateKey) ;
				msg.encrypt(authPublicKey, KeyType.Public);
				out.writeObject(msg);
				//-------------------------
				InputStream inFromServer = socket.getInputStream();
				ObjectInputStream in = new ObjectInputStream(inFromServer);
				
				Object input = in.readObject() ;
				//-------------------------
				ans = (Msg) input ;
				ans.setEncryptionMethod(Msg.Encryption_RSA) ;
				ans.encrypt(privateKey, KeyType.Private) ;
				ans.validate(authPublicKey) ;
				
				map.put(index, ans.get("session")) ;
				
				socket.close();
			}
			process(map);
		} catch (IOException e) {
			// TODO Auto-generated catch block
//			e.printStackTrace();
			throw new NetworkErrorException() ;
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
//			e.printStackTrace();
			throw new NetworkErrorException() ;
		}
	}


	private void process(HashMap<Integer, byte[]> map) {
		for (Integer index : map.keySet()) {
			try {
				System.out.print(index);
				Helper.printByteArray(map.get(index));
				
				byte[] session = map.get(index);
				Msg msg = new Msg() ;
				msg.put("vote", enc_votes.get(index)) ;
				
				msg.setEncryptionMethod(Msg.Encryption_AES);
				msg.encrypt(session, KeyType.SYM_DEC);
				
				String vote = new String(msg.get("vote"));
				
				
				System.out.println("Vote for #" + index + " = " + vote) ;
				
				if ( answers.containsKey(vote) == false )
					answers.put(vote, 0) ;
				answers.put(vote, answers.get(vote) + 1) ;
				if (max_vote_cnt < answers.get(vote)){
					max_vote = vote ;
					max_vote_cnt = answers.get(vote) ; 
				}
			} catch (NotValidMsgException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			 
 		}
		System.out.println("Winner is " + max_vote + " with #" + max_vote_cnt);
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
				ans.encrypt(null, KeyType.NONE) ;
				ans.validate(null) ;
				//-------------------------
				byte[] index = getIndex(ans.get("vote")) ;
				//-------------------------
				Msg msg = new Msg() ;
				msg.put("index", index);
				msg.setEncryptionMethod(Msg.Encryption_NONE) ;
				msg.sign(privateKey) ;
				msg.encrypt(null, KeyType.NONE);
				//-------------------------
				ObjectOutputStream out = new ObjectOutputStream(server.getOutputStream());
				out.writeObject(msg);
				
				server.close();
			}catch(SocketTimeoutException s)
			{
//				System.out.println("Socket timed out!");
				break;
			}catch(IOException e)
			{
//				e.printStackTrace();
				break;
			} catch (NotValidMsgException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
//				e.printStackTrace();
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
