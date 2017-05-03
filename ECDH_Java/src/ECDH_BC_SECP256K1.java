import java.math.BigInteger;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.Security;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

public class ECDH_BC_SECP256K1
{
	final private static String pathA = "a.ecc";
	final protected static char[] hexArray = "0123456789abcdef".toCharArray();
	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}

	public static byte [] savePublicKey (PublicKey key) throws Exception
	{
		ECPublicKey eckey = (ECPublicKey)key;
		return eckey.getQ().getEncoded(true);
	}

	public static PublicKey loadPublicKey (byte [] data) throws Exception
	{
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
		ECPublicKeySpec pubKey = new ECPublicKeySpec(
				params.getCurve().decodePoint(data), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(pubKey);
	}

	public static byte [] savePrivateKey (PrivateKey key) throws Exception
	{
		ECPrivateKey eckey = (ECPrivateKey)key;
		return eckey.getD().toByteArray();
	}

	public static PrivateKey loadPrivateKey (byte [] data) throws Exception
	{
		PrivateKey key;
		ECParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
		ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), params);
		KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePrivate(prvkey);
	}

	/**
	 * @param name
	 * @param dataPrv
	 * @param dataPub
	 * @throws Exception
	 */
	public static void doECDH (String name, byte[] dataPrv, byte[] dataPub) throws Exception
	{
		KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
		PrivateKey prvk = loadPrivateKey(dataPrv);
		PublicKey pubk = loadPublicKey(dataPub);
		ka.init(prvk);
		ka.doPhase(pubk, true);
		byte [] secret = ka.generateSecret();
		System.out.println(name + bytesToHex(secret));
	}

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main (String [] args) throws Exception
	{
		KeyPair pairA;
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator kpgen = KeyPairGenerator.getInstance("ECDH", "BC");
		kpgen.initialize(new ECGenParameterSpec("secp256k1"), new SecureRandom());

        if(!FileUtil.IsKeyExist(pathA)) {
		pairA = kpgen.generateKeyPair();
		FileUtil.generatorKey(pairA, pathA);
        } else {
        	pairA = FileUtil.getSecretKey(pathA);
        }

		byte [] dataPrvA = savePrivateKey(pairA.getPrivate());
		byte [] dataPubA = savePublicKey(pairA.getPublic());

		System.out.println("Alice Prv: " + bytesToHex(dataPrvA));
		System.out.println("Alice Pub: " + bytesToHex(dataPubA));
        //This pubkey from openssl
        String dataC = "021debb5ca31ad676a24ea8580fd42f6fcd10eb46680b78f5474a61791b513dc0e";
        System.out.println("Bob Pub: " + dataC);
		doECDH("Alice's secret: ", dataPrvA, Numeric.hexStringToByteArray(dataC));
	}
}
