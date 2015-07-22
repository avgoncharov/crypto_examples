package ru.avgoncharov.pkcs10;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.OperatorCreationException;

import java.security.cert.X509Certificate;

/**
 * Created by a.v.goncharov on 22.07.2015.
 * Simple implementation ContentVerifierProvider interface for GOST algorithms.
 */
public class GostContentVerifierProvider implements org.bouncycastle.operator.ContentVerifierProvider {
	//region Ctor.
	public GostContentVerifierProvider(X509Certificate certificate) { this.certificate = certificate; }
	//endregion

	//region Public.
	@Override
	public boolean hasAssociatedCertificate() {
		return true;
	}

	@Override
	public X509CertificateHolder getAssociatedCertificate() {
		try {
			return new X509CertificateHolder(certificate.getEncoded());
		}
		catch(Exception ex) {
			return null;
		}
	}

	@Override
	public ContentVerifier get(AlgorithmIdentifier algorithmIdentifier) throws OperatorCreationException {
		try {
			return new GostContentVerifier(certificate);
		}
		catch(Exception ex) {
			throw new OperatorCreationException(ex.getMessage(), ex);
		}
	}
	//endregion

	//region Fields.
	private X509Certificate certificate;
	//endregion

}
