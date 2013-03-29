package net.fatfredyy.certgenerator.keypair;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fest.assertions.Assertions;
import org.junit.BeforeClass;
import org.junit.Test;

public class RSAKeyPairGeneratorTest {
	
	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Test
	public void shoudReturnNOTNullKeyPair() throws Exception {
		//given
		KeyPair generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);
		
		//then
		Assertions.assertThat(generatedKeyPair).isNotNull();
	}
	
	
	@Test
	public void shouldPublicKeySpecBeConsistent() throws Exception {
		//given
		KeyPair generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);
		
		//when
		RSAPublicKey rsaPublicKey = (RSAPublicKey) generatedKeyPair.getPublic();
		BigInteger publicExponent = rsaPublicKey.getPublicExponent();
		BigInteger modulus = rsaPublicKey.getModulus();
		
		//then
		Assertions.assertThat(publicExponent).isEqualTo(RSAKeyGenParameterSpec.F4);
		Assertions.assertThat(modulus.bitLength()).isEqualTo(1024);
	}
	
	@Test
	public void shouldPrivateKeySpecBeConsistent() throws Exception {
		//given
		KeyPair generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);
		
		//when
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) generatedKeyPair.getPrivate();
		BigInteger modulus = rsaPrivateKey.getModulus();
		
		//then
		Assertions.assertThat(modulus.bitLength()).isEqualTo(1024);
	}
	
	@Test
	public void shouldSignAndVerifyCorrectly() throws Exception {
		// given
		KeyPair generatedKeyPair = RSAKeyPairGenerator.generateRSAKeyPair(1024, RSAKeyGenParameterSpec.F4);

		// when
		Signature signer = Signature.getInstance("SHA1withRSA", "BC");
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
