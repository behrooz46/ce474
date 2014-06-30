package ca;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;

import sun.security.x509.*;

import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
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

import common.Helper;


public class SignServer{

	private X509Certificate caCert;
	private KeyPair caPair;

	public SignServer(String publicFile, String privateFile){
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		caPair = new KeyPair(Helper.loadPublicKey(publicFile), Helper.loadPrivateKey(privateFile));
		caCert = generateSelfSignedX509Certificate();
	}
	
		
	@SuppressWarnings("deprecation")
	public X509Certificate generateSelfSignedX509Certificate(){
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
//			printCert(cert);
			return cert;
		}
		catch(Exception e){
			System.err.println("Error occured while trying to generate certificate");
			e.printStackTrace();
			return null;
		}
	}
	
	public static boolean verify(X509Certificate cert, PublicKey key){
		try {
			cert.verify(key);
			return true;
		} catch (InvalidKeyException | CertificateException
				| NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e) {
			// TODO Auto-generated catch block
			return false;
		}
	}
	
	public PublicKey getPublicKey(){
		return caPair.getPublic();
	}
	
	
	public static void main(String[] args) {
		try{
			SignServer ss = new SignServer("public_key.der", "private_key.der");
			
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGenerator.initialize(1024, new SecureRandom());
		  
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			X509Certificate cert = ss.createCert(keyPair.getPublic(), "Farhad Shahmohammadi");
			System.out.println(SignServer.verify(cert, ss.getPublicKey()));
		}
		catch(Exception e){
			
		}
	}
	
	
	
}
