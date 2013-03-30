package net.fatfredyy.certgenerator.cert;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

import net.fatfredyy.certgenerator.keypair.RSAKeyPairGenerator;
import net.fatfredyy.certgenerator.test.CertInfoUtil;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fest.assertions.Assertions;
import org.junit.BeforeClass;
import org.junit.Test;

public class RSACertificateCreatorTest {
	
	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void shoudCreateNotNullCertificate() throws Exception {
		// given
		RSACertificateCreator rsaCertificateCreator = new RSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair ecKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);
		
		//when
		X509Certificate certificate = rsaCertificateCreator.createSelfSignedCertificate(ecKeyPair, "SHA1withRSA");
		
		// then
		Assertions.assertThat(certificate).isNotNull();
	}
	
	@Test
	public void shoudCreateCertificateWithGivenPublicKey() throws Exception {
		// given
		RSACertificateCreator rsaCertificateCreator = new RSACertificateCreator(CertInfoUtil.getNotBeforeDate(),
				CertInfoUtil.getNotAfterDate(), CertInfoUtil.getSubject(), BigInteger.ONE);
		KeyPair ecKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);
		
		//when
		X509Certificate certificate = rsaCertificateCreator.createSelfSignedCertificate(ecKeyPair, "SHA1withRSA");
		RSAPublicKey pairRSAPublicKey = (RSAPublicKey) ecKeyPair.getPublic();
		RSAPublicKey certRSAPublicKey = (RSAPublicKey) certificate.getPublicKey();
		
		// then
		Assertions.assertThat(certRSAPublicKey.getModulus()).isEqualTo(pairRSAPublicKey.getModulus());
	}

}
