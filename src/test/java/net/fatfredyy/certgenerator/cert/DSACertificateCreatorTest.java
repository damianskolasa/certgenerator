package net.fatfredyy.certgenerator.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;

import net.fatfredyy.certgenerator.keypair.DSAKeyPairGenerator;
import net.fatfredyy.certgenerator.test.CertInfoUtil;
import net.fatfredyy.certgenerator.test.SignatureUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fest.assertions.Assertions;
import org.junit.BeforeClass;
import org.junit.Test;

public class DSACertificateCreatorTest {

	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void shoudCreateNotNullCertificate() throws Exception {
		// given
		DSACertificateCreator dsaCertificateCreator = new DSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair keyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);

		// when
		X509Certificate certificate = dsaCertificateCreator.createSelfSignedCertificate(keyPair, "SHA1withDSA");

		// then
		Assertions.assertThat(certificate).isNotNull();
	}

	@Test
	public void shoudCreateCertificateWithGivenPublicKey() throws Exception {
		// given
		DSACertificateCreator dsaCertificateCreator = new DSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair keyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);

		// when
		X509Certificate certificate = dsaCertificateCreator.createSelfSignedCertificate(keyPair, "SHA1withDSA");
		DSAPublicKey pairDSAPublicKey = (DSAPublicKey) keyPair.getPublic();
		DSAPublicKey certDSAPublicKey = (DSAPublicKey) certificate.getPublicKey();

		// then
		Assertions.assertThat(certDSAPublicKey.getY()).isEqualTo(pairDSAPublicKey.getY());
	}

	@Test
	public void shoudSignAndVerifyCorrectlyFromCertificate() throws Exception {
		// given
		DSACertificateCreator dsaCertificateCreator = new DSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair keyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);

		// when
		X509Certificate certificate = dsaCertificateCreator.createSelfSignedCertificate(keyPair, "SHA1withDSA");
		DSAPublicKey pairDSAPublicKey = (DSAPublicKey) keyPair.getPublic();
		DSAPublicKey certDSAPublicKey = (DSAPublicKey) certificate.getPublicKey();

		// then
		Assertions.assertThat(SignatureUtil.testSignAndVerify(keyPair.getPrivate(), certDSAPublicKey, "SHA1withDSA")).isTrue();
		Assertions.assertThat(SignatureUtil.testSignAndVerify(keyPair.getPrivate(), pairDSAPublicKey, "SHA1withDSA")).isTrue();
	}

}
