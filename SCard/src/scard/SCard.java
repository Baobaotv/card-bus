package SCard;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SCard extends Applet
{
	private static byte[] pintemp, sothe, hoten, ngaysinh;
	private OwnerPIN pin;
	private static short sodu, pinlen, sothelen, hotenlen, ngaysinhlen, count;
	private final static byte CLA = (byte) 0xA0;
	//image
	private byte[] image1,image2,image3,image4;
    private short imagelen1,imagelen2,imagelen3,imagelen4, lenback1, lenback2, lenback3,lenback4, pointer1,pointer2, pointer3, pointer4;
    public static final short MAX_LENGTH = (short)(0x7FFF);
    
	//khai bao INS apdu lenh
	private final static byte INS_INIT_INFO = (byte) 0x10;
	private final static byte INS_GETINFO = (byte) 0x11;
	private final static byte INS_SETIMG = (byte) 0x12;
	private final static byte INS_GETIMG = (byte) 0x13;
	private final static byte INS_UPDATE_INFO = (byte) 0x14;
	private final static byte INS_UPDATE_PIN = (byte) 0x15;
	private final static byte INS_BALANCE = (byte) 0x16;
	private final static byte INS_PAY = (byte)0x17;
	private final static byte INS_CLEARCARD = (byte) 0x18;
	private final static byte INS_CHECKPIN = (byte) 0x19;
	private final static byte INS_UNBLOCK = (byte) 0x20;
	private final static byte INS_GETSD = (byte) 0x21;	
	private final static byte INS_GETPUBKEY = (byte) 0x22;

	
	private MessageDigest md5;
	private Cipher aescipher;
	private AESKey aesKey;
	private final static byte PIN_trylimit= (byte)0x03;
	private final static byte PIN_maxsize= (byte)0x44;
	private final static byte[] status = {(byte)0x00,(byte)0x01,(byte)0x02};
    final private byte[] tempBuffer, pintoKey, sig_buffer, rsaPriKey, rsaPubKey;
	private Signature rsaSig;
	private short sigLen, rsaPriKeyLen, rsaPubKeyLen;
	private RandomData ranData;
	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new SCard();
	}
	public SCard(){
		// thong tin
		pin =new OwnerPIN(PIN_trylimit, PIN_maxsize);
		pintemp = new byte[44];
		sothe = new byte[32];
		hoten = new byte[64];
		ngaysinh = new byte[16];
		pintoKey = new byte[16];
		sodu = 0;
		// image 
		image1 = new byte[MAX_LENGTH];
		image2 = new byte[MAX_LENGTH];
		image3 = new byte[MAX_LENGTH];
		image4 = new byte[MAX_LENGTH];
		//aes
		md5 = MessageDigest.getInstance(MessageDigest.ALG_MD5,false);
		aescipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,KeyBuilder.LENGTH_AES_128,false);
		
		//rsa sig
        sigLen = (short)(KeyBuilder.LENGTH_RSA_1024/8);
        rsaPriKey= new byte[(short)(sigLen*2)];
		rsaPubKey = new byte[(short)(sigLen*2)];
		rsaPubKeyLen = 0;
        rsaPriKeyLen = 0;
		sig_buffer = new byte[sigLen];
		rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
		tempBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
		register();
		JCSystem.requestObjectDeletion();
	}
	public void process(APDU apdu){
		if (selectingApplet()){
			return;
		}
		byte[] buf = apdu.getBuffer();
		short len = apdu.setIncomingAndReceive();
		if(buf[ISO7816.OFFSET_CLA] != CLA) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_INIT_INFO:
			init_info(apdu, len);
			break;
		case INS_GETINFO:
			get_info(apdu);
			break;
		case INS_SETIMG:
			if(buf[ISO7816.OFFSET_P1] == 0x01){
				imagelen1 = 0;
				imagelen2 = 0;
				imagelen3 = 0;
				imagelen4 = 0;
			}
			if(buf[ISO7816.OFFSET_P1] == 0x02){
				set_img(apdu, len);
			}
			break;
		case INS_GETIMG:
			if(buf[ISO7816.OFFSET_P1] == 0x01){
				lenback1= imagelen1;
				lenback2= imagelen2;
				lenback3= imagelen3;
				lenback4= imagelen4;
				pointer1=0;
				pointer2=0;
				pointer3=0;
				pointer4=0;
				if(imagelen2 ==0){
					lenback2=1;
				}
				if(imagelen3==0){
					lenback3=1;
				}
				if(imagelen4==0){
					lenback4=1;
				}
			}
			if(buf[ISO7816.OFFSET_P1] ==0x02){
				get_img(apdu);
			}
			break;
		case INS_UPDATE_INFO:
			update_info(apdu,len);
			break;
		case INS_UPDATE_PIN:
			update_pin(apdu, len);
			break;
		case INS_BALANCE:
			update_balance(apdu,len);
			break;
		case INS_PAY:
			pay(apdu, len);
			break;
		case INS_CLEARCARD:
			clear_card(apdu);
			break;
		case INS_CHECKPIN:
			check_pin(apdu, len);
			break;
		case INS_UNBLOCK:
			unblock_card(apdu);
			break;
	    case INS_GETSD:
	    	getsodu(apdu);
	    	break;
	    case INS_GETPUBKEY:
	    	getPublicKey(apdu,len);
	    	break;
		default: 
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void init_info(APDU apdu, short len){
		short t1,t2,t3;
		t1=t2=t3= 0;
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short)0, len);
		for(short i=0; i<len ; i++){
			if(tempBuffer[i] == (byte) 0x2e){
				if(t1 ==0){
					t1 = i;
					sothelen = (short)t1;
				}else {
					if(t2 ==0){
						t2=i;
						hotenlen = (short)(t2-t1-1);
					}else {
						if(t3 == 0){
							t3=i;
							ngaysinhlen = (short)(t3-t2-1);
							pinlen = (short)(len-t3-1);
						}
					}
				}
			}
		}
		Util.arrayCopy(tempBuffer, (short)0, sothe, (short)0,sothelen);
		Util.arrayCopy(tempBuffer, (short)(t1+1), hoten, (short)0,hotenlen);
		Util.arrayCopy(tempBuffer, (short)(t2+1), ngaysinh, (short)0,ngaysinhlen);
		Util.arrayCopy(tempBuffer, (short)(t3+1), pintemp, (short)0,pinlen);
		//pin.update(pintemp, (short)0, (byte)pinlen);
		//tao cap khoa
		genKeypair(apdu);
		setAesKey(apdu,pintemp, pinlen);
		//ma hoa PIN
		encrypt_AesCipher(apdu,pintemp, (short)pinlen);
		//them pin vao the
		pin.update(pintemp, (short)0, (byte)pinlen);
		//ma hoa rsaPriKey
		encrypt_AesCipher(apdu,rsaPriKey, (short)rsaPriKeyLen);

		Util.arrayFillNonAtomic(tempBuffer, sothelen, (short) 1, (byte)0x3A);
		//dau :
		Util.arrayFillNonAtomic(tempBuffer, (short) (sothelen + hotenlen + 1), (short) 1, (byte) 0x3A);
		Util.arrayFillNonAtomic(tempBuffer, (short) (sothelen + hotenlen + ngaysinhlen + 2), (short) 1, (byte) 0x3A);

		short totallen = (short)(sothelen+hotenlen+ngaysinhlen+2);
	
		Util.arrayCopy(tempBuffer, (short)0, buffer, (short)0, (short)(totallen));
		apdu.setOutgoingAndSend((short)0,(short)(totallen));
	}
    private void get_info(APDU apdu){
	    byte[] buffer = apdu.getBuffer();
        short len= (short)(sothelen+ hotenlen+ngaysinhlen+2);
     
         Util.arrayCopy(sothe,(short)0, tempBuffer, (short)0, sothelen);
         Util.arrayCopy(hoten,(short)0, tempBuffer, (short)(sothelen+1), hotenlen);
         Util.arrayCopy(ngaysinh,(short)0, tempBuffer, (short)(sothelen + hotenlen+ 2), ngaysinhlen);

     
        Util.arrayFillNonAtomic(tempBuffer, sothelen, (short) 1, (byte) 0x3A);//dau :
		Util.arrayFillNonAtomic(tempBuffer, (short)(sothelen+hotenlen+1), (short)1, (byte) 0x3A);
		Util.arrayFillNonAtomic(tempBuffer, (short) (sothelen+ hotenlen+ngaysinhlen+2), (short) 1, (byte) 0x3A);
	
		Util.arrayCopy(tempBuffer, (short)0, buffer, (short) 0, len);
        apdu.setOutgoingAndSend((short)0, len);
}
	private void clear_card(APDU apdu) {
		sodu = (short)0;
		pinlen = (short)0;
		sothelen = (short) 0 ;
        hotenlen = (short) 0;
        ngaysinhlen = (short) 0;
        Util.arrayFillNonAtomic(sothe, (short) 0, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(hoten, (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(ngaysinh, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(pintemp, (short) 0, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(pintoKey, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(rsaPriKey, (short) 0, (short)(2*128), (byte) 0);
        Util.arrayFillNonAtomic(rsaPubKey, (short) 0, (short)(2*128), (byte) 0);
        Util.arrayFillNonAtomic(sig_buffer, (short) 0, (short)(128), (byte) 0);
    }
    private void set_img(APDU apdu, short len){
    	byte[] buf = apdu.getBuffer();
		short offData = apdu.getOffsetCdata();
        if((short)(MAX_LENGTH-imagelen3)<255){
	        Util.arrayCopy(buf, offData, image4, imagelen4, len);
	        imagelen4 += len;
        }else{
            if((short)(MAX_LENGTH-imagelen2)<255){
	            Util.arrayCopy(buf, offData, image3, imagelen3, len);
				imagelen3 += len;
             }else{
	           	if((short)(MAX_LENGTH-imagelen1)<255){
					Util.arrayCopy(buf, offData, image2, imagelen2, len);
					imagelen2 += len;
				}else{
					Util.arrayCopy(buf, offData, image1, imagelen1, len);
					imagelen1 += len;
				}
           	 }
           }
	    }
	    
    private void get_img(APDU apdu){
    	byte[] buf = apdu.getBuffer();
		short datalen = 255;
        if(lenback3==0){
        	if(lenback4 <255){
	        	datalen = lenback4;
        	}
	        apdu.setOutgoing();
			apdu.setOutgoingLength((short)255);
			Util.arrayCopy(image4, (pointer4), buf, (short)0, datalen);
			apdu.sendBytes((short)0, datalen);
			pointer4+=  (short)255;
			lenback4 -= (short)(255);
        }else{
	        if(lenback2==0){
	        	if(lenback3 <255){
					datalen = lenback3;
				}
				apdu.setOutgoing();
				apdu.setOutgoingLength((short)255);
				Util.arrayCopy(image3, (pointer3), buf, (short)0, datalen);
				apdu.sendBytes((short)0, datalen);
				pointer3+=  (short)255;
				lenback3 -= (short)(255);
			}else{
				if(lenback1==0){
					if(lenback2 <255){
						datalen = lenback2;
					}
					apdu.setOutgoing();
					apdu.setOutgoingLength((short)255);
					Util.arrayCopy(image2, (pointer2), buf, (short)0, datalen);
					apdu.sendBytes((short)0, datalen);
					pointer2+=  (short)255;
					lenback2 -= (short)(255);
				}else{
					if(lenback1 <255){
						datalen = lenback1;
					}
					apdu.setOutgoing();
					apdu.setOutgoingLength((short)255);
					Util.arrayCopy(image1, (pointer1), buf, (short)0, datalen);
					apdu.sendBytes((short)0, datalen);
					pointer1+=  (short)255;
					lenback1 -= (short)(255);
					}
				}
        	}
	    }
	    
    private void check_pin(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)3);
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short)0, len);
        encrypt_AesCipher(apdu,tempBuffer, (short)len);
        if (pin.getTriesRemaining() != 0){
        	if(pin.check(tempBuffer,(short)0, (byte)len) == true) {
				apdu.sendBytesLong(status,(short) 1, (short) 1);//gui 1
				}else apdu.sendBytesLong(status,(short)0,(short)1); // gui 0
        }else apdu.sendBytesLong(status, (short)2, (short) 1);//gui 2
    }
    
    private  void unblock_card(APDU apdu){
        pin.resetAndUnblock();
    }
    
    private void  setAesKey(APDU apdu, byte[] in, short len){
    	byte[] buffer = apdu.getBuffer();
	    short md5len = md5.doFinal(in, (short)0, (short)len, buffer, (short)0);
	    JCSystem.beginTransaction();
	    Util.arrayCopy(buffer , (short)0, pintoKey, (short)0, (short)md5len);
	    JCSystem.commitTransaction();
	    JCSystem.requestObjectDeletion();
	    }
	    
	private void encrypt_AesCipher(APDU apdu, byte[] in, short inlen) {
        try {
        	byte[] buffer = apdu.getBuffer();
            aesKey.setKey(pintoKey, (short)0);//set khoa tu PIN
            byte mod = Cipher.MODE_ENCRYPT;
            if(inlen <= 0){ ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }else if(inlen % 16 == 0){
				aescipher.init(aesKey, mod);
				aescipher.doFinal(in, (short) 0, inlen, in, (short) 0);
			}else if (inlen <16){
				byte[] a= new byte[(short)(16-inlen)];
				for(short i=0; i<(short)(16-inlen);i++){
					a[i] = (byte)(i+1); 
				}
				aescipher.init(aesKey, mod);
				aescipher.update(in,(short)0,(short)(inlen),buffer,(short)0);
				aescipher.doFinal(a, (short) 0, (short)(16-inlen), buffer, (short)0);
				Util.arrayCopy(buffer, (short)0, in, (short)0, (short)16);
			}else{
				byte[] b= new byte[16];
				count=0;
				for(short i=0; i<inlen; i++){
					b[count] = in[i];
					count++;
					if(count== 16){
						aescipher.init(aesKey, mod);
						aescipher.doFinal(b,(short)0,(short)(b.length),buffer,(short)(i-15));
						count = 0;
					}
					if(i==(short)(inlen-1)){
						byte[] a= new byte[(short)(16-count)];
						for(short j=0; j<(short)(16-count);j++){
							a[j] = (byte)(j+1);
						}
						aescipher.init(aesKey, mod);
						aescipher.update(b,(short)0,(short)(count),buffer,(short)(i-count+1));
						aescipher.doFinal(a, (short) 0, (short)(a.length), buffer, (short)(i-count+1));
						Util.arrayCopy(buffer, (short)0, in, (short)0, (short)(inlen+16-count));
						//apdu.setOutgoingAndSend((short)0, (short)(inlen+16-count));
						break;
					}
				}
			}
			JCSystem.requestObjectDeletion();
        }catch (CryptoException e) {
            short reason = e.getReason();
            ISOException.throwIt(reason);
        }
    }
    
    private void decrypt_AesCipher(APDU apdu, byte[] in, short inlen,byte[] out, short offset){
    	byte[] buffer = apdu.getBuffer();
    	byte mod = Cipher.MODE_DECRYPT;
	    if(inlen % 16 == 0){
			aescipher.init(aesKey, mod);
			aescipher.doFinal(in, (short) 0, inlen, out, (short)offset);
		}else if (inlen <16){
			aescipher.init(aesKey, mod);
			aescipher.doFinal(in, (short) 0, (short)16, buffer, (short)0);
			Util.arrayCopy(buffer, (short)0, out, (short)offset, (short)inlen);
		}else{
			count=0;
			for(short i=1; i<=inlen; i++){
				if(i % 16 == 0 ){
					count++;
					aescipher.init(aesKey, mod);
					aescipher.doFinal(in,(short)(i-16),(short)16,buffer,(short)(i-16));
				}
			}
			aescipher.init(aesKey, mod);
			aescipher.doFinal(in, (short)(16*count), (short)16, buffer, (short)(16*count));
			Util.arrayCopy(buffer, (short)0, out, (short)offset, (short)(inlen));
		}
		JCSystem.requestObjectDeletion();	
    }
    
    private short setoutlen(short inlen){
	    if(inlen <= 0){ ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	    }else if(inlen <= 16){ inlen = 16;
	    }else{
	    	count=1;
	    	for(short i=1; i<=inlen; i++){
	    		if(i % 16 ==0) count++;
	    	}
	    	inlen = (short)(16*count);
	    }
	    return inlen;
    }
    
    private void genKeypair(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA,(short)(8*sigLen));
		keyPair.genKeyPair();
		JCSystem.beginTransaction();
        rsaPubKeyLen = 0;
        rsaPriKeyLen = 0;
        JCSystem.commitTransaction();
		RSAPublicKey pubKey = (RSAPublicKey)keyPair.getPublic();
        short pubKeyLen = 0;
        pubKeyLen += pubKey.getModulus(rsaPubKey, pubKeyLen);//N
        pubKeyLen += pubKey.getExponent(rsaPubKey, pubKeyLen);//E
		short priKeyLen = 0;
        RSAPrivateKey priKey = (RSAPrivateKey)keyPair.getPrivate();
        priKeyLen += priKey.getModulus(rsaPriKey, priKeyLen);//N
        priKeyLen += priKey.getExponent(rsaPriKey, priKeyLen);//D
        JCSystem.beginTransaction();
		rsaPubKeyLen = pubKeyLen;//do dai khóa RSA pub
		rsaPriKeyLen = priKeyLen;// khóa RSA private
		JCSystem.commitTransaction();
		JCSystem.requestObjectDeletion();
    }
    
    private void createSig(APDU apdu,short len){
	    byte[] buffer = apdu.getBuffer();
	    byte[] OTP = new byte[6];
	    short OTPlen = 6;
	    byte[] tempPriKey = new byte[(short)(256)];
	    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short)0, len);
	    Util.arrayCopy(tempBuffer, (short)(0), OTP, (short)0, OTPlen);
	    Util.arrayCopy(tempBuffer, (short)OTPlen, pintemp, (short)0, (short)(len-OTPlen));
	    encrypt_AesCipher(apdu,pintemp, (short)pinlen);
        if(pin.check(pintemp, (short)0, (byte)pinlen) == true) {
        	decrypt_AesCipher(apdu, rsaPriKey, rsaPriKeyLen, tempPriKey, (short)0);
        	RSAPrivateKey PriKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,KeyBuilder.LENGTH_RSA_1024, false);
			PriKey.setModulus(tempPriKey, (short)0, (short)(128));
			PriKey.setExponent(tempPriKey, (short)128,(short)(128));
			rsaSig.init(PriKey, Signature.MODE_SIGN);
		    rsaSig.sign(OTP, (short)0, (short)(OTPlen),sig_buffer, (short)0);
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)sigLen);
			apdu.sendBytesLong(sig_buffer, (short)0, (short)sigLen);
        }else apdu.sendBytesLong(status,(short)0,(short)1); // gui 0
        JCSystem.requestObjectDeletion();
    }
    
    private void verifySigSuccess(APDU apdu, short len, short mod){
    	byte [] buffer = apdu.getBuffer();
    	byte[] OTP = new byte[6];
    	//byte[] tempPubKey = new byte[rsaPubKeyLen];
	    short OTPlen = 6;
	    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short)0, len);
	    Util.arrayCopy(tempBuffer, (short)0, OTP, (short)0, OTPlen);
	    short money=0;
	    
	    if((short)(len-OTPlen) != (short)1){
	    	if((short)(len-OTPlen) ==3){
		    	money += (short)(tempBuffer[OTPlen]*256);
		    	money += (short)(tempBuffer[OTPlen+1]*16);
		    	money += (short)(tempBuffer[OTPlen+2]);
	    	}
	    	if((short)(len-OTPlen) ==4){
		    	money += (short)(tempBuffer[OTPlen]*256*16);
		    	money += (short)(tempBuffer[OTPlen+1]*256);
		    	money += (short)(tempBuffer[OTPlen+2]*16);
		    	money += (short)(tempBuffer[OTPlen+3]);
	    	}
	    }else{
		    money += tempBuffer[OTPlen];
	    }
	   
			if(mod == 0){
				if ( (short)(sodu + money)  > MAX_LENGTH ){
					Util.arrayCopy(status, (short)2, buffer, (short)0, (short)1);//gui 2
				}
				sodu += (short)money;
				Util.arrayCopy(status, (short)1, buffer, (short)0, (short)1);
			}
			
			if(mod == 1){
				if ( (short)money<(short)0 || (short)sodu < (short)money ) 
				{
					Util.arrayCopy(status, (short)2, buffer, (short)0, (short)1);//gui 2
					}
				if(sodu >= (short)money)
				{
					sodu -= money;
					Util.arrayCopy(status, (short)1, buffer, (short)0, (short)1);
				} 
			}
		
		apdu.setOutgoingAndSend((short)0, (short)1);
		JCSystem.requestObjectDeletion();
    }
    
    private void getPublicKey(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        short offset = (short) 128;
        switch (buffer[ISO7816.OFFSET_P1])
		{
			case (byte) 0x01 :
				Util.arrayCopy(rsaPubKey, (short) 0, buffer, (short) 0, offset);
				apdu.setOutgoingAndSend((short) 0, offset);
				break;
				
			case (byte) 0x02 :
				short eLen = (short) (rsaPubKeyLen - offset);
				Util.arrayCopy(rsaPubKey, offset, buffer, (short) 0, eLen);
				apdu.setOutgoingAndSend((short) 0, eLen);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
    }
    
    private void update_balance(APDU apdu,short len){
    	byte[] buffer = apdu.getBuffer();
	    
	    if(buffer[ISO7816.OFFSET_P1] == 0x01){
		    createSig(apdu, len);
	    }
	    if(buffer[ISO7816.OFFSET_P1] == 0x02){
		    verifySigSuccess(apdu, len,(short)0);
	    }
    }
    
    private void pay(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    
	    if(buffer[ISO7816.OFFSET_P1] == 0x01){
		    createSig(apdu, len);
	    }
	    if(buffer[ISO7816.OFFSET_P1] == 0x02){
		    verifySigSuccess(apdu, len, (short)1);
	    }
    }
    
    private void update_pin(APDU apdu,short len){
	    byte[] buffer = apdu.getBuffer();
	    apdu.setOutgoing();
	    apdu.setOutgoingLength((short)1);
	    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pintemp, (short)0, len);
	    if(len>6 && len <= PIN_maxsize){
	    	pinlen = len;
	    	encrypt_AesCipher(apdu,pintemp, (short)pinlen);
		    pin.update(pintemp, (short)0, (byte)len);
		    apdu.sendBytesLong(status, (short)1, (short)1);//gui 1
	    }else apdu.sendBytesLong(status, (short)0, (short)1);//gui 0
    }
    
    private void update_info(APDU apdu,short len){
    	
	    short t1,t2;
		t1=t2= 0;
		byte[] buffer = apdu.getBuffer();
		Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short)0, len);
		for(short i=0; i<len ; i++){
			if(tempBuffer[i] == (byte) 0x2e){
				if(t1 ==0){
					t1 = i;
					sothelen = (short)t1;
				}else {
					if(t2 ==0){
						t2=i;
						hotenlen = (short)(t2-t1-1);
						ngaysinhlen = (short)(len-t2-1);
					}
					}
				}
			}
		Util.arrayCopy(tempBuffer, (short)0, sothe, (short)0,sothelen);
		Util.arrayCopy(tempBuffer, (short)(t1+1), hoten, (short)0,hotenlen);
		Util.arrayCopy(tempBuffer, (short)(t2+1), ngaysinh, (short)0,ngaysinhlen);
	
    }
    
    private void getsodu(APDU apdu){
    	byte[] buffer = apdu.getBuffer();
    	Util.setShort(buffer, (short)0, sodu);
	    apdu.setOutgoingAndSend((short)0, (short)(2));
    }
}