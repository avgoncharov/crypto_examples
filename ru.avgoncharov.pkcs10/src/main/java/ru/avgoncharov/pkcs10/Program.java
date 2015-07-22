package ru.avgoncharov.pkcs10;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import java.security.*;
import java.security.cert.X509Certificate;


/**
 * Created by a.v.goncharov on 14.07.2015.
 * This program generate PKCS10 request by using Russian GOST Keys and Certs. *
 */
public class Program {
	public static void main(String[] args){
		String storageName = "Your storage name.";
		String alias = "key store alias.";
		String password = null;

		KeyStore ks = loadKeyStore(storageName);
		KeyPair pair = loadKeyPair(ks, alias, password);
		X509Certificate cert = getCert(ks, alias);

		try {
			PKCS10CertificationRequest csr = DirectRequestBuilder.createRequest(cert, pair);
			System.out.printf("[DirectRequestBuilder] Request is valid: %b\n", csr.isSignatureValid(new GostContentVerifierProvider(cert)));

			csr = SimpleRequestBuilder.createRequest(cert, pair);
			System.out.printf("[SimpleRequestBuilder] Request is valid: %b\n", csr.isSignatureValid(new GostContentVerifierProvider(cert)));
		}catch (Throwable th){
			th.printStackTrace();
			System.exit(1);
		}
	}

	private static KeyPair loadKeyPair(KeyStore ks, String alias, String password)  {
		try {
			PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password == null ? null : password.toCharArray());
			X509Certificate certificate = (X509Certificate) ks.getCertificate(alias);
			KeyPair pair = new KeyPair(certificate.getPublicKey(), privateKey);
			return pair;
		}catch (Throwable th){
			th.printStackTrace();
			System.exit(1);
		}
		return null;
	}

	private static X509Certificate getCert(KeyStore ks, String alias)
	{
		try {
			return (X509Certificate) ks.getCertificate(alias);
		}catch (Throwable th){
			th.printStackTrace();
			System.exit(1);
		}
		return null;
	}

	private static KeyStore loadKeyStore(String storageName){
		try {
			KeyStore ks = KeyStore.getInstance(storageName);
			ks.load(null);
			return ks;
		}
		catch (Throwable th){
			th.printStackTrace();
			System.exit(1);
		}
		return null;
	}
}
