package net.fatfredyy.certgenerator.keypair;

import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fest.assertions.Assertions;
import org.junit.BeforeClass;
import org.junit.Test;

public class ECKeyPairGeneratorTest {
	
	@BeforeClass
	public static void beforeClass() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Test
	public void shoudReturnNOTNullKeyPair() throws Exception {
		//given
		KeyPair generatedKeyPair = ECKeyPairGenerator.generateECKeyPair("prime192v1");
		
		//then
		Assertions.assertThat(generatedKeyPair).isNotNull();
	}
	
	
	@Test
	public void shouldPublicKeyFieldSizeBe192() throws Exception {
		//given
		KeyPair generatedKeyPair = ECKeyPairGenerator.generateECKeyPair("prime192v1");
		
		//when
		ECPublicKey ecPublicKey = (ECPublicKey) generatedKeyPair.getPublic();
		int curveFiledSize = ecPublicKey.getParameters().getCurve().getFieldSize();
		
		//then
		Assertions.assertThat(curveFiledSize).isEqualTo(192);
	}
	
	@Test
	public void shouldPrivateKeyFieldSizeBe192() throws Exception {
		//given
		KeyPair generatedKeyPair = ECKeyPairGenerator.generateECKeyPair("prime192v1");
		
		//when
		ECPrivateKey ecPrivateKey = (ECPrivateKey) generatedKeyPair.getPrivate();
		int curveFiledSize = ecPrivateKey.getParameters().getCurve().getFieldSize();
		
		//then
		Assertions.assertThat(curveFiledSize).isEqualTo(192);
	}
	
	@Test
	public void shouldSignAndVerifyCorrectly() throws Exception {
		//given
		KeyPair generatedKeyPair = ECKeyPairGenerator.generateECKeyPair("prime192v1");
		
		//when
		Signature signer = Signature.getInstance("SHA1withECDSA", "BC");
	    signer.initSign(generatedKeyPair.getPrivate());
	    signer.update("TestSignatureString".getBytes());
	    byte[] signature = signer.sign();

	    signer.initVerify(generatedKeyPair.getPublic());
	    signer.update("TestSignatureString".getBytes());
	    boolean signatureValid = signer.verify(signature);
	    
		//then
		Assertions.assertThat(signatureValid).isTrue();
	}

}
