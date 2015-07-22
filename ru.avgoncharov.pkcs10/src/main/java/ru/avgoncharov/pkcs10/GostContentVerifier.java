package ru.avgoncharov.pkcs10;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import ru.CryptoPro.JCP.JCP;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.Signature;
import java.security.cert.X509Certificate;

/**
 * Created by a.v.goncharov on 22.07.2015.
 * Simple implementation ContentVerifier interface for GOST algorithms.
 */
public class GostContentVerifier implements org.bouncycastle.operator.ContentVerifier {
	//region Ctor.
	public GostContentVerifier(X509Certificate certificate) throws
			java.security.NoSuchAlgorithmException,
			java.security.InvalidKeyException
	{
		signature = Signature.getInstance(JCP.GOST_DHEL_SIGN_NAME);
		signature.initVerify(certificate);
		buffer = new ByteArrayOutputStream();
	}
	//endregion

	//region Public.
	@Override
	public AlgorithmIdentifier getAlgorithmIdentifier() {
		return new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.643.2.2.3"));
	}

	@Override
	public OutputStream getOutputStream() {
		return buffer;
	}

	@Override
	public boolean verify(byte[] var1) {
		try
		{
			signature.update(buffer.toByteArray());
			return signature.verify(var1);
		}
		catch(java.security.SignatureException ex)
		{
			return false;
		}
	}
	//endregion

	//region Fields.
	private Signature signature;
	private ByteArrayOutputStream buffer;
	//endregion
}
