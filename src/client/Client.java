package client;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Scanner;

public class Client {
	private static final String id = "1";
	private String cert, publicKey;
	
	private String caServerName;
	private int caServerPort;
	private String collectServerName;
	private int collectServerPort;
	private String authServerName;
	private int authServerPort;

	public Client(String fileName) throws IOException {
		// TODO read conf file
		caServerName = "localhost";
		caServerPort = 2222;
		authServerName = "localhost";
		authServerPort = 3333;
		collectServerName = "localhost";
		collectServerPort = 4444;
		//----------------------- read public key
		BufferedReader reader = new BufferedReader(new FileReader("src/client/"+ this.id +"/publickey.pem"));
		String line = null ; publicKey = "" ;
		while ((line = reader.readLine()) != null) {
			publicKey += line ;
			publicKey += "\n" ;
		}
		reader.close();
	}

	public static void main(String[] args) throws IOException {
		
		Scanner cin = new Scanner(System.in);
		Client client = new Client("conf.txt") ;
		
		
		while(true){
			String cmd = cin.next() ;
			if (cmd.equals("Exit")){
				break ;
			}else if (cmd.equals("Sign")){
				try
				{
					Socket socket = new Socket(client.caServerName, client.caServerPort);
					
					OutputStream outToServer = socket.getOutputStream();
					DataOutputStream out = new DataOutputStream(outToServer);
					String publicKey = client.getPublickKey() ;
					out.writeUTF(publicKey);
					
					InputStream inFromServer = socket.getInputStream();
					DataInputStream in = new DataInputStream(inFromServer);
					String cert = in.readUTF() ;
					socket.close();
					
					client.setCertificate(cert); 
				}catch(IOException e)
				{
					e.printStackTrace();
				}
			}else if (cmd.equals("Session")){
				try
				{
					Socket socket = new Socket(client.collectServerName, client.collectServerPort);
					
					OutputStream outToServer = socket.getOutputStream();
					DataOutputStream out = new DataOutputStream(outToServer);
					String cert = client.getCert() ;
					out.writeUTF(cert);
					
					InputStream inFromServer = socket.getInputStream();
					DataInputStream in = new DataInputStream(inFromServer);
					String session = in.readUTF() ;
					socket.close();
					
					client.setSession(session); 
				}catch(IOException e)
				{
					e.printStackTrace();
				}
			}else if (cmd.equals("Vote")){
				try
				{
					Socket socket = new Socket(client.collectServerName, client.collectServerPort);
					
					OutputStream outToServer = socket.getOutputStream();
					DataOutputStream out = new DataOutputStream(outToServer);
					String cert = client.getCert() ;
					out.writeUTF(cert);
					
					InputStream inFromServer = socket.getInputStream();
					DataInputStream in = new DataInputStream(inFromServer);
					String session = in.readUTF() ;
					socket.close();
					
					client.setSession(session); 
				}catch(IOException e)
				{
					e.printStackTrace();
				}
			}else{
				System.out.println("Available Commands Are:\n1- Sign\n2- Auth\n3- Vote <name>\n4- Exit");
			}

		}
		cin.close(); 
	}

	private void setSession(String session) {
		// TODO Auto-generated method stub
		
	}

	private String getCert() {
		// TODO Auto-generated method stub
		return "Cert";
	}

	private void setCertificate(String cert) {
		this.cert = cert ;
		
	}

	private String getPublickKey(){
		return publicKey	 ;
	}
}
