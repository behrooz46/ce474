package ca;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;

public class VerifyServer extends Thread {

	private ServerSocket serverSocket;

	public VerifyServer(int port) throws IOException {
		serverSocket = new ServerSocket(port);
		//		serverSocket.setSoTimeout(10000);
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
				DataOutputStream out = new DataOutputStream(server.getOutputStream());
				out.writeUTF("ok");
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

}
