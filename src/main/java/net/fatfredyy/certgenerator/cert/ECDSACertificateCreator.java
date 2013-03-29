package net.fatfredyy.certgenerator.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class ECDSACertificateCreator extends CertificateCreator {
	
	public ECDSACertificateCreator(Date notBefore, Date notAfter, String subject, BigInteger serialNumber) {
		super(notBefore, notAfter, subject, serialNumber);
	}

	@Override
	public X509Certificate createSelfSignedCertificate(KeyPair keyPair, String contentSignAlg) throws Exception {

		registerContentSigner(contentSignAlg, keyPair.getPrivate());

		BCECPublicKey ecPublicKey = (BCECPublicKey) keyPair.getPublic();
		ECParameterSpec ecParamsSpec = ecPublicKey.getParameters();

		X9ECParameters ecParameters = new X9ECParameters(ecParamsSpec.getCurve(), ecParamsSpec.getG(), ecParamsSpec.getN());

		ASN1OctetString asn1Point = (ASN1OctetString) new X9ECPoint(ecPublicKey.getQ()).toASN1Primitive();

		SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
				new X962Parameters(ecParameters)), asn1Point.getOctets());

		X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject,
				pubKeyInfo);

		X509CertificateHolder certHolder = v1CertGen.build(contentSigner);
		X509Certificate generatedCertificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

		serialNumber = serialNumber.add(BigInteger.ONE);
		return generatedCertificate;

	}

}
