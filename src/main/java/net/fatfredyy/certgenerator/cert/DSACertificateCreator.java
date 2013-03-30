package net.fatfredyy.certgenerator.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

public class DSACertificateCreator extends CertificateCreator {

	public DSACertificateCreator(Date notBefore, Date notAfter, String subject, BigInteger serialNumber) {
		super(notBefore, notAfter, subject, serialNumber);
	}

	@Override
	public X509Certificate createSelfSignedCertificate(KeyPair keyPair, String contentSignAlg) throws Exception {

		registerContentSigner(contentSignAlg, keyPair.getPrivate());

		DSAPublicKey dsaPublicKey = (DSAPublicKey) keyPair.getPublic();
		DSAParams dsaParams = dsaPublicKey.getParams();
		DSAParameter dsaParameter = new DSAParameter(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());

		SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa,
				dsaParameter.toASN1Primitive()), new ASN1Integer(dsaPublicKey.getY()));

		X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject, pubKeyInfo);

		X509CertificateHolder certHolder = v1CertGen.build(contentSigner);
		X509Certificate generatedCertificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

		serialNumber = serialNumber.add(BigInteger.ONE);
		return generatedCertificate;

	}

}
