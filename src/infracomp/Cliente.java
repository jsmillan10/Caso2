package infracomp;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

public class Cliente {

	boolean ejecutar = true;
	Socket sock = null;
	PrintWriter escritor = null;
	BufferedReader lector = null;

	public Cliente()
	{
		try {
			sock = new Socket("localhost", 8083);
			escritor = new PrintWriter(sock.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(
					sock.getInputStream()));
			comenzarComunicacion(lector, escritor);
		} catch (Exception e) {
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}
	}
	// cierre el socket y la entrada estándar

	public void comenzarComunicacion(BufferedReader lector, PrintWriter escritor) throws Exception
	{
		escritor.println("HOLA");
		String respuesta = lector.readLine();
		System.out.println(respuesta);
		if(respuesta.equals("OK"))
		{
			escritor.println("ALGORITMOS:AES:RSA:HMACSHA256");
			respuesta = lector.readLine();
			System.out.println(respuesta);
			if(respuesta.equals("OK"))
			{
				String certHecho = generarCertificado();
				escritor.println("CERTCLNT:" + certHecho);
				String certRecibido = "";
				while(!(respuesta=lector.readLine()).contains("END CERTIFICATE"))
				{
					certRecibido+=respuesta;
				}
				int reto = (int) (Math.random()*10000+1);
				//Hay que revisar que se le envíe al servidor una cadena de números par como 01 o 4875 o 195723
				System.out.println(reto);
				byte[] hexa = DatatypeConverter.parseHexBinary(""+reto);
				escritor.println(reto);
				respuesta = lector.readLine();
				System.out.println(respuesta);
			}
		}

	}

	public String generarCertificado() throws Exception {

		Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		// in 2 years
		Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);

		// GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024, new SecureRandom());

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// GENERATE THE X509 CERTIFICATE
		X509V3CertificateGenerator v3Cert = new X509V3CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=JSM");

		v3Cert.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		v3Cert.setSubjectDN(dnName);
		v3Cert.setIssuerDN(dnName); // use the same
		v3Cert.setNotBefore(validityBeginDate);
		v3Cert.setNotAfter(validityEndDate);
		v3Cert.setPublicKey(keyPair.getPublic());
		//si es HMACSHA1-->SHA1withRSA
		//si es HMACMD5-->MD5withRSA
		//si es HMACSHA256-->SHA256withRSA
		v3Cert.setSignatureAlgorithm("SHA256withRSA");

		X509Certificate cert = v3Cert.generate(keyPair.getPrivate());
		StringWriter out = new StringWriter();
		PemWriter pem = new PemWriter(out);
		pem.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
		pem.flush();
		pem.close();
		out.close();
		String result = out.toString();
		return result;
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		new Cliente();
	}

}
