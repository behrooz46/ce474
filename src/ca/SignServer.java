package ca;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;

import sun.security.x509.*;

import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.*;
import java.math.BigInteger;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;


public class SignServer{

	private X509Certificate caCert;
	private KeyPair caPair;

	public SignServer(String publicFile, String privateFile){
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		caPair = new KeyPair(readPublicKey(publicFile), loadPrivateKey(privateFile));
		caCert = generateSelfSignedX509Certificate();
	}
	
	private PrivateKey loadPrivateKey(String privateFile){
		try{
			File f = new File(privateFile);
		    FileInputStream fis = new FileInputStream(f);
		    DataInputStream dis = new DataInputStream(fis);
		    byte[] keyBytes = new byte[(int)f.length()];
		    dis.readFully(keyBytes);
		    dis.close();
	
		    PKCS8EncodedKeySpec spec =
		      new PKCS8EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePrivate(spec);
		}
		catch(Exception e){
			System.err.println("Error occured while trying to load private key");
			e.printStackTrace();
			return null;
		}
	}
	
	private PublicKey readPublicKey(String publicFile){
		try{
			File f = new File(publicFile);
		    FileInputStream fis = new FileInputStream(f);
		    DataInputStream dis = new DataInputStream(fis);
		    byte[] keyBytes = new byte[(int)f.length()];
		    dis.readFully(keyBytes);
		    dis.close();

		    X509EncodedKeySpec spec =
		      new X509EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    return kf.generatePublic(spec);
		}
		catch(Exception e){
			System.err.println("Error occured while trying to load public key");
			e.printStackTrace();
			return null;
		}
	}
	
	@SuppressWarnings("deprecation")
	private X509Certificate generateSelfSignedX509Certificate(){
		try{
		    Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		    Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);
	
		    X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
		    X500Principal dnName = new X500Principal("CN=My CA");
	
		    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		    certGen.setSubjectDN(dnName);
		    certGen.setIssuerDN(dnName); // use the same
		    certGen.setNotBefore(validityBeginDate);
		    certGen.setNotAfter(validityEndDate);
		    certGen.setPublicKey(caPair.getPublic());
		    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
	
		    X509Certificate cert = certGen.generate(caPair.getPrivate(), "BC");
	
		    return cert;
		}
		catch(Exception e){
			System.err.println("Error occured while trying to generate ca certificate");
			e.printStackTrace();
			return null;
		}
	}
	
	@SuppressWarnings("deprecation")
	public X509Certificate createCert(PublicKey publicKey, String sName){
		try{
			Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);       
			Date expiryDate = new Date(System.currentTimeMillis() + 1 * 365 * 24 * 60 * 60 * 1000);
			BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
			PrivateKey caKey = caPair.getPrivate();             
			
			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
			X500Principal subjectName = new X500Principal("CN=" + sName);
			 
			certGen.setSerialNumber(serialNumber);
			certGen.setIssuerDN(caCert.getSubjectX500Principal());
			certGen.setNotBefore(startDate);
			certGen.setNotAfter(expiryDate);
			certGen.setSubjectDN(subjectName);
			certGen.setPublicKey(publicKey);
			certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
			
			certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
			                        new AuthorityKeyIdentifierStructure(caCert));
			certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
			                        new SubjectKeyIdentifierStructure(publicKey));
			 
			X509Certificate cert = certGen.generate(caKey, "BC");
			printCert(cert);
			return cert;
		}
		catch(Exception e){
			System.err.println("Error occured while trying to generate certificate");
			e.printStackTrace();
			return null;
		}
	}
	
	
	private void printCert(X509Certificate cert){
		System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println("CERTIFICATE TO_STRING");
	    System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println();
	    System.out.println(cert);
	    System.out.println();

	    System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println("CERTIFICATE PEM");
	    System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println();
	    try{
		    PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
		    pemWriter.writeObject(cert);
		    pemWriter.flush();
		    System.out.println();
		    pemWriter.close();
	    }
	    catch(Exception e){
	    	e.printStackTrace();
	    }
	}
	
	public static void main(String[] args) {
		try{
			SignServer ss = new SignServer("public_key.der", "private_key.der");
			
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGenerator.initialize(1024, new SecureRandom());
		  
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			ss.createCert(keyPair.getPublic(), "Farhad Shahmohammadi");
		}
		catch(Exception e){
			
		}
	}
	
}
