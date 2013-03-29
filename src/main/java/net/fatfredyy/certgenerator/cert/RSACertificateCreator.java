package net.fatfredyy.certgenerator.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;

public class RSACertificateCreator extends CertificateCreator {

	public RSACertificateCreator(Date notBefore, Date notAfter, String subject, BigInteger serialNumber) {
		super(notBefore, notAfter, subject, serialNumber);
	}

	@Override
	public X509Certificate createSelfSignedCertificate(KeyPair keyPair, String contentSignAlg) throws Exception {

		registerContentSigner(contentSignAlg, keyPair.getPrivate());
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
		
		RSAKeyParameters rsaKeyParameters = new RSAKeyParameters(false, rsaPublicKey.getModulus(), rsaPublicKey.getPublicExponent());
		
		SubjectPublicKeyInfo pubKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(rsaKeyParameters);

		X509v1CertificateBuilder v1CertGen = new X509v1CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject,
				pubKeyInfo);

		X509CertificateHolder certHolder = v1CertGen.build(contentSigner);
		X509Certificate generatedCertificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

		serialNumber = serialNumber.add(BigInteger.ONE);
		return generatedCertificate;

	}
}
