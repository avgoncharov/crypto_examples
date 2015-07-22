package ru.avgoncharov.pkcs10;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by a.v.goncharov on 22.07.2015.
 * Build PKCS10 request by JcaPKCS10CertificationRequestBuilder.
 */
public class SimpleRequestBuilder {
	//region Public.
	public static PKCS10CertificationRequest createRequest(X509Certificate certificate, KeyPair keyPair) throws Throwable{
		org.bouncycastle.asn1.x509.Certificate v = org.bouncycastle.asn1.x509.Certificate.getInstance(certificate.getEncoded());

		PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(v.getSubject(), keyPair.getPublic());
		addAtributes(requestBuilder, certificate);

		return requestBuilder.build(new GostCryptoSigner(keyPair.getPrivate()));
	}
	//endregion

	//region Private.
	private static void addAtributes(PKCS10CertificationRequestBuilder requestBuilder, X509Certificate cert)throws Throwable {
		List<Extension> exs = new ArrayList<Extension>();
		boolean found252919 = false;
		final String id252919 = "2.5.29.19";

		final String dontUse = "1.3.6.1.5.5.7.1.1";
		final String[] needToBe = {"2.5.29.32","1.2.643.100.111","2.5.29.19" ,"2.5.29.37"};


		for (String id : cert.getCriticalExtensionOIDs()){
			if(!InArray(needToBe, id))
				continue;

			if(id.compareTo(id252919) == 0)
				found252919 = true;

			ASN1ObjectIdentifier asn1Id = new ASN1ObjectIdentifier(id);
			ASN1OctetString val = DEROctetString.getInstance(cert.getExtensionValue(id));
			org.bouncycastle.asn1.x509.Extension x = new org.bouncycastle.asn1.x509.Extension(asn1Id, new ASN1Boolean(true), val);

			exs.add(x);
		}

		for (String id : cert.getNonCriticalExtensionOIDs()){
			if(!InArray(needToBe, id))
				continue;

			if(id.compareTo(id252919) == 0)
				found252919 = true;

			ASN1ObjectIdentifier asn1Id = new ASN1ObjectIdentifier(id);
			ASN1OctetString val = DEROctetString.getInstance(cert.getExtensionValue(id));
			org.bouncycastle.asn1.x509.Extension x = new org.bouncycastle.asn1.x509.Extension(asn1Id, new ASN1Boolean(false), val);

			exs.add(x);
		}

		if(!found252919) {
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

		requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, es);
	}

	private static boolean InArray(String[] needToBe, String id) {
		for(String str: needToBe)
			if(str.compareTo(id) == 0)
				return true;

		return false;
	}
	//endregion
}
