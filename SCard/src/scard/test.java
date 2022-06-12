package SCard;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
public class test extends Applet
{
	private static final byte INS_SIGN = (byte)0x00;
	private static final byte INS_VERIFY = (byte)0x01;

	private RSAPrivateKey rsaPrivKey;
	private RSAPublicKey rsaPubKey;
	private Signature rsaSig;

	private byte[] s1, s2, s3, sig_buffer;

	private short sigLen;

	private test()
	{
		s1 = new byte[]{0x01, 0x02, 0x03};
		s2 = new byte[]{0x04, 0x05};
		s3 = new byte[]{0x06, 0x07, 0x08};
		sigLen = (short)(KeyBuilder.LENGTH_RSA_1024/8);
		sig_buffer = new byte[sigLen];
		rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
		rsaPrivKey =(RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,(short)(8*sigLen),false);
		rsaPubKey =(RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,(short)(8*sigLen), false);
		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA,(short)(8*sigLen));
		keyPair.genKeyPair();
		rsaPrivKey = (RSAPrivateKey)keyPair.getPrivate();
		rsaPubKey = (RSAPublicKey)keyPair.getPublic();
	}
	public static void install(byte[] bArray, short bOffset,byte bLength)
	{
		new test().register(bArray, (short) (bOffset +1), bArray[bOffset]);
	}
	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_SIGN:
			rsaSign(apdu);
			break;
		case INS_VERIFY:
			rsaVerify(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	private void rsaSign(APDU apdu)
	{
		rsaSig.init(rsaPrivKey, Signature.MODE_SIGN);
		rsaSig.update(s1, (short)0, (short)(s1.length));
		rsaSig.update(s2, (short)0, (short)(s2.length));
		rsaSig.sign(s3, (short)0, (short)(s3.length),sig_buffer, (short)0);
		apdu.setOutgoing();
		apdu.setOutgoingLength(sigLen);
		apdu.sendBytesLong(sig_buffer, (short)0, sigLen);
	}
	private void rsaVerify(APDU apdu)
	{
		byte [] buf = apdu.getBuffer();
		rsaSig.init(rsaPubKey, Signature.MODE_VERIFY);
		rsaSig.update(s1, (short)0, (short)(s1.length));
		rsaSig.update(s2, (short)0, (short)(s2.length));
		boolean ret = rsaSig.verify(s3, (short)0,(short)(s3.length), sig_buffer, (short)0, sigLen);
		buf[(short)0] = ret ? (byte)1 : (byte)0;
		apdu.setOutgoingAndSend((short)0, (short)1);
	}
}
