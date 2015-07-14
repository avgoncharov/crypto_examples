import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import ru.CryptoPro.Crypto.CryptoProvider;

import java.io.FileWriter;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by a.v.goncharov on 14.07.2015.
 * This program generate PKCS10 request by using Russian GOST Keys and Certs. *
 */
public class Program {
	public static void main(String[] args){

		String storageName = "Your storage name.";
		String alias = "key store alias.";
		String password = null;

		Security.addProvider(new CryptoProvider());

		KeyStore ks = loadKeyStore(storageName);
		KeyPair pair = loadKeyPair(ks, alias, null);
		X509Certificate cert = getCert(ks, alias);

		//To be able using gost-key for signing, we have to use CryptoPto signer.
		ru.CryptoPro.JCP.Sign.CryptoProSign signer = new ru.CryptoPro.JCP.Sign.CryptoProSign();

		try {
			signer.initSign(pair.getPrivate());

			//For correct transformation to CertificateRequestInfo.
			org.bouncycastle.asn1.x509.Certificate v = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());

			//Form attributes.
			ASN1Set attributes = formAttributes(cert);

			CertificationRequestInfo crtInfo = new CertificationRequestInfo(v.getSubject(), v.getSubjectPublicKeyInfo(), attributes);
			signer.update(crtInfo.getEncoded());

			PKCS10CertificationRequest csr = new PKCS10CertificationRequest(new CertificationRequest(crtInfo, new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.643.2.2.3")), new DERBitString(signer.sign())));

			String str = Base64.toBase64String(csr.getEncoded());

			String fileName = "Your file name for result.";
			FileWriter fw = new FileWriter(fileName);
			fw.write(str);
			fw.close();
		}catch (Throwable th){
			th.printStackTrace();
			System.exit(1);
		}
	}

	private static ASN1Set formAttributes(X509Certificate cert) throws Throwable
	{
		List<Extension> exs = new ArrayList<Extension>();
		boolean found252919 = false;
		final String id252919 = "2.5.29.19";

		for (String id : cert.getCriticalExtensionOIDs()){
			if(id.compareTo(id252919) == 0)
				found252919 = true;

			ASN1ObjectIdentifier asn1Id = new ASN1ObjectIdentifier(id);
			ASN1OctetString val = DEROctetString.getInstance(cert.getExtensionValue(id));
			org.bouncycastle.asn1.x509.Extension x = new org.bouncycastle.asn1.x509.Extension(asn1Id, new ASN1Boolean(true), val);

			exs.add(x);
		}

		for (String id : cert.getNonCriticalExtensionOIDs()){
			if(id.compareTo(id252919) == 0)
				found252919 = true;

			ASN1ObjectIdentifier asn1Id = new ASN1ObjectIdentifier(id);
			ASN1OctetString val = DEROctetString.getInstance(cert.getExtensionValue(id));
			org.bouncycastle.asn1.x509.Extension x = new org.bouncycastle.asn1.x509.Extension(asn1Id, new ASN1Boolean(false), val);

			exs.add(x);
		}

		if(!found252919) {
			//If we don't have.
			ASN1ObjectIdentifier asn1Id = new ASN1ObjectIdentifier("2.5.29.19");
			BasicConstraints bc = new BasicConstraints(0);
			byte[] binVal = bc.getEncoded();
			ASN1OctetString val = new DEROctetString(binVal);
			org.bouncycastle.asn1.x509.Extension x = new org.bouncycastle.asn1.x509.Extension(asn1Id, new ASN1Boolean(true), val);

			exs.add(x);
		}

		org.bouncycastle.asn1.x509.Extension[] buf = new org.bouncycastle.asn1.x509.Extension[exs.size()];
		exs.toArray(buf);

		org.bouncycastle.asn1.x509.Extensions es = new org.bouncycastle.asn1.x509.Extensions(buf);

		ASN1ObjectIdentifier pkcs9Id = PKCSObjectIdentifiers.pkcs_9_at_extensionRequest;
		ASN1Set bs = new BERSet(es);
		ASN1Encodable[] vec =  {pkcs9Id, bs};

		return new DERSet(new org.bouncycastle.asn1.DERSequence(vec));
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
