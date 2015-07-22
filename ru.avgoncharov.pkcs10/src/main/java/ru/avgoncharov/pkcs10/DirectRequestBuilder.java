package ru.avgoncharov.pkcs10;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;

import java.io.FileWriter;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by a.v.goncharov on 22.07.2015.
 * Build PKCS10 request without any other builders.
 */
public class DirectRequestBuilder {

	//region Public.
	public static PKCS10CertificationRequest createRequest(X509Certificate certificata, KeyPair keyPair) throws Throwable {
		//For correct transformation to CertificateRequestInfo.
		org.bouncycastle.asn1.x509.Certificate v = org.bouncycastle.asn1.x509.Certificate.getInstance(certificata.getEncoded());

		//Form attributes.
		ASN1Set attributes = formAttributes(certificata);

		CertificationRequestInfo crtInfo = new CertificationRequestInfo(v.getSubject(), v.getSubjectPublicKeyInfo(), attributes);

		ru.CryptoPro.JCP.Sign.GostElSign signer = new ru.CryptoPro.JCP.Sign.GostElSign();
		signer.initSign(keyPair.getPrivate());
		signer.update(crtInfo.getEncoded());

		return new PKCS10CertificationRequest(new CertificationRequest(crtInfo, new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.643.2.2.3")), new DERBitString(signer.sign())));
	}
	//endregion

	//region Private.
	private static ASN1Set formAttributes(X509Certificate cert) throws Throwable
	{
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

	private static boolean InArray(String[] needToBe, String id) {
		for(String str: needToBe)
			if(str.compareTo(id) == 0)
				return true;

		return false;
	}
	//endregion



}
