package ca;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import sun.security.x509.*;

import java.security.cert.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.*;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.Strings;
//import org.bouncycastle.x509.X509Util;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;


public class SignServer extends Thread {

	private ServerSocket serverSocket;
	static private X509Certificate caCert;
	static private KeyPair caPair;
//	private String caFile, caPassword, caAlias;
//	private RSAPrivateCrtKeyParameters caPrivateKey;
//	private String exportPassword, exportFile;

	
	public SignServer(int port) throws IOException {
		serverSocket = new ServerSocket(port);
		//		serverSocket.setSoTimeout(10000);
	}

	@Override
	public void run() {
		while(true)
		{
			try
			{
//				System.out.println("Waiting for client on port " + serverSocket.getLocalPort() + "...");
				Socket server = serverSocket.accept();
//				System.out.println("Just connected to " + server.getRemoteSocketAddress());
				DataInputStream in = new DataInputStream(server.getInputStream());
				String publicKey = in.readUTF() ;
				
				DataOutputStream out = new DataOutputStream(server.getOutputStream());
				
//				X509Certificate cert = sign("CN", keyPair, 365, "SHA1withRSA");
				out.writeUTF("cert");
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


	/** 
	 * Create a self-signed X.509 Certificate
	 * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
	 * @param pair the KeyPair
	 * @param days how many days from now the Certificate is valid for
	 * @param algorithm the signing algorithm, eg "SHA1withRSA"
	 */ 
	X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
	  throws GeneralSecurityException, IOException
	{
	  PrivateKey privkey = pair.getPrivate();
	  X509CertInfo info = new X509CertInfo();
	  Date from = new Date();
	  Date to = new Date(from.getTime() + days * 86400000l);
	  CertificateValidity interval = new CertificateValidity(from, to);
	  BigInteger sn = new BigInteger(64, new SecureRandom());
	  X500Name owner = new X500Name(dn);
	 
	  info.set(X509CertInfo.VALIDITY, interval);
	  info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
	  info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
	  info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
	  info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
	  info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
	  AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
	  info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
	 
	  // Sign the cert to identify the algorithm that's used.
	  X509CertImpl cert = new X509CertImpl(info);
	  cert.sign(privkey, algorithm);
	 
	  // Update the algorith, and resign.
	  algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
	  info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
	  cert = new X509CertImpl(info);
	  cert.sign(privkey, algorithm);
	  return cert;
	}
			
	
	@SuppressWarnings("deprecation")
	static private X509Certificate generateSelfSignedX509Certificate() throws Exception {


	    // yesterday
	    Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
	    // in 2 years
	    Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);

	    // GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
	    keyPairGenerator.initialize(1024, new SecureRandom());

	    KeyPair keyPair = keyPairGenerator.generateKeyPair();

	    // GENERATE THE X509 CERTIFICATE
	    X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
	    X500Principal dnName = new X500Principal("CN=John Doe");

	    certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
	    certGen.setSubjectDN(dnName);
	    certGen.setIssuerDN(dnName); // use the same
	    certGen.setNotBefore(validityBeginDate);
	    certGen.setNotAfter(validityEndDate);
	    certGen.setPublicKey(keyPair.getPublic());
	    certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

	    X509Certificate cert = certGen.generate(keyPair.getPrivate(), "BC");

	    // DUMP CERTIFICATE AND KEY PAIR

//	    printCert(cert);
	    	    
	    caCert = cert;
	    caPair = keyPair;
	    return cert;
	}
	
	static private void createCert() throws NoSuchAlgorithmException, NoSuchProviderException{
		Date startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);                // time from which certificate is valid
		Date expiryDate = new Date(System.currentTimeMillis() + 1 * 365 * 24 * 60 * 60 * 1000);               // time after which certificate is not valid
		BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());       // serial number for certificate
		PrivateKey caKey = caPair.getPrivate();              // private key of the certifying authority (ca) certificate
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
	    keyPairGenerator.initialize(1024, new SecureRandom());

	    KeyPair keyPair = keyPairGenerator.generateKeyPair();
	    

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal              subjectName = new X500Principal("CN=Test V3 Certificate");
		 
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(caCert.getSubjectX500Principal());
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(subjectName);
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
		
		try{
			certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
			                        new AuthorityKeyIdentifierStructure(caCert));
			certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
			                        new SubjectKeyIdentifierStructure(keyPair.getPublic()));
			 
			X509Certificate cert = certGen.generate(caKey, "BC");   // note: private key of CA
			printCert(cert);
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			generateSelfSignedX509Certificate();
			createCert();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	static private void printCert(X509Certificate cert){
		System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println("CERTIFICATE TO_STRING");
	    System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println();
	    System.out.println(cert);
	    System.out.println();

	    System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println("CERTIFICATE PEM (to store in a cert-johndoe.pem file)");
	    System.out.println(new String(new char[80]).replace("\0", "="));
	    System.out.println();
	    try{
		    PEMWriter pemWriter = new PEMWriter(new PrintWriter(System.out));
		    pemWriter.writeObject(cert);
		    pemWriter.flush();
		    System.out.println();
	    }
	    catch(Exception e){
	    	
	    }

//	    System.out.println(new String(new char[80]).replace("\0", "="));
//	    System.out.println("PRIVATE KEY PEM (to store in a priv-johndoe.pem file)");
//	    System.out.println(new String(new char[80]).replace("\0", "="));
//	    System.out.println();
//	    pemWriter.writeObject(keyPair.getPrivate());
//	    pemWriter.flush();
//	    System.out.println();
	}
	
}
