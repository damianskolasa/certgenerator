package net.fatfredyy.certgenerator.keypair;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fest.assertions.Assertions;
import org.junit.BeforeClass;
import org.junit.Test;

public class DSAKeyPairGeneratorTest {

	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void shoudReturnNOTNullKeyPair() throws Exception {
		// given
		KeyPair generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);

		// then
		Assertions.assertThat(generatedKeyPair).isNotNull();
	}

	@Test
	public void shouldPublicKeySpecBeConsistent() throws Exception {
		// given
		KeyPair generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);

		// when
		DSAPublicKey dsaPublicKey = (DSAPublicKey) generatedKeyPair.getPublic();
		BigInteger q = dsaPublicKey.getParams().getQ();
		BigInteger p = dsaPublicKey.getParams().getP();

		// then
		Assertions.assertThat(q.bitLength()).isEqualTo(160);
		Assertions.assertThat(p.bitLength()).isEqualTo(1024);
	}

	@Test
	public void shouldPrivateKeySpecBeConsistent() throws Exception {
		// given
		KeyPair generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);

		// when
		DSAPrivateKey dsaPrivateKey = (DSAPrivateKey) generatedKeyPair.getPrivate();
		BigInteger x = dsaPrivateKey.getX();

		// then
		Assertions.assertThat(x.bitLength()).isGreaterThan(0).isLessThanOrEqualTo(160);
	}

	@Test
	public void shouldSignAndVerifyCorrectly() throws Exception {
		// given
		KeyPair generatedKeyPair = DSAKeyPairGenerator.generateDSAKeyPair(1024, 160);

		// when
		Signature signer = Signature.getInstance("SHA1withDSA", "BC");
		signer.initSign(generatedKeyPair.getPrivate());
		signer.update("TestSignatureString".getBytes());
		byte[] signature = signer.sign();

		signer.initVerify(generatedKeyPair.getPublic());
		signer.update("TestSignatureString".getBytes());
		boolean signatureValid = signer.verify(signature);

		// then
		Assertions.assertThat(signatureValid).isTrue();
	}

}
