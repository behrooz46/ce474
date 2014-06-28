

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;


public class Collector extends Thread {

	private ServerSocket serverSocket;

	public Collector(int port) throws IOException {
		serverSocket = new ServerSocket(port);
	}

	@Override
	public void run() {
		while(true)
		{
			try
			{
				Socket server = serverSocket.accept();
				DataInputStream in = new DataInputStream(server.getInputStream());
				String cert = in.readUTF() ;
				
				if ( validate(cert) ){
					DataOutputStream out = new DataOutputStream(server.getOutputStream());
					out.writeUTF("session");
				}else{
					DataOutputStream out = new DataOutputStream(server.getOutputStream());
					out.writeUTF("session");
				}
				
				server.close();
			}catch(SocketTimeoutException s)
			{
				System.out.println("Socket timed out!");
				break;
			}catch(IOException e)
			{
				e.printStackTrace();
				break;
			}
		}
	}

	private boolean validate(String cert) {
		return false;
	}
}
