package ca;

import java.io.IOException;


public class CA extends Thread{
	public SignServer signServer;
	public VerifyServer verifyServer; 

	public CA(String fileName) throws IOException {
		// TODO read conf file
		signServer = new SignServer(2222) ;
		verifyServer = new VerifyServer(3333) ;
	}

	public static void main(String[] args) {
		try
		{
			CA ca = new CA("conf.txt") ;
			ca.signServer.start();
			ca.verifyServer.start() ;
		}catch(IOException e)
		{
			e.printStackTrace();
		}

	}
}
