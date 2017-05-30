package be.msec.smartcard;


//import java.util.Arrays;

//import be.msec.client.RandomData;
//import be.msec.client.bte;

//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import javax.crypto.Cipher;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.security.*;
import javacard.framework.Util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
//import javacardx.crypto.Cipher;


//// in client not card
//import javacard.security.*;
//import javacardx.crypto.*;  //creating keys for use in symmetric algorithms

public class IdentityCard extends Applet {
//	CLA code in CommandAPDU header
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	
//	INS codes
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_SERIAL_INS = 0x24;
	private static final byte GEN_NONCE = 0x20;
	private final static byte PIN_TRY_LIMIT =(byte)0x03;
	private final static byte PIN_SIZE =(byte)0x04;
	private final static byte REQ_VALIDATION_INS=(byte)0x16;
		
//	//INS codes for different SPs
	private final static byte GET_eGov_DATA=(byte)0x05;
	private final static byte GET_Health_DATA=(byte)0x06;	
	private final static byte GET_SN_DATA=(byte)0x07;
	private final static byte GET_def_DATA=(byte)0x08;
	//	TS_DATA: first check lastVal. time and update, diff . e.g. set at 24 hrs 
	private final static byte GET_TS_DATA=(byte)0x09; //timestamp
	private final static byte SET_Data=(byte)0x10;
	private final static byte Set_PIN=(byte)0x15;
	private final static byte GET_pubKey=(byte)0x19;
	private final static byte GET_Exponent=(byte)0x17;
	private final static byte GET_Modulus=(byte)0x18;
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	private static final APDU APDU = null;
	
////	instance variables declaration
	private byte[] serial = new byte[]{0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05};
	private OwnerPIN pin;
//	//individuals identified by a service-specific pseudonym
//	private byte[] nym_Gov = new byte[]{0x11}; // to have something to test data saving on javacard
//	private byte[] nym_Health = new byte[]{0x12};
//	private byte[] nym_SN = new byte[]{0x13};
//	private byte[] nym_def = new byte[]{0x14};

////	instance variables
//	private byte[] name = new byte[]{0x01,0x02,0x03,0x04};
	private byte[] name = {'i', 'n', 's', 'e', 'r', 't',' ', 'c','h','a','r'};
//	private byte[] address;
//	private byte[] country;
//	private byte[] birthdate;
//	private byte[] age;
//	private byte[] gender;
//	private byte[] picture;
//	private byte[] bloodType;
	
	//personal informationn saved on card
	//input above instance variables into info below
	private byte[] info;
	private short incomingData;
//	private short newPin;

	
//	data for certification and encryption/decryption, time needed for cert verification
	private byte[] lastValidationTime = new byte[11]; //time format: "yyyy-D HH:mm:ss"
	private byte[] currentTime = new byte[11];
//	private byte[] nonce  = new byte[]{(byte)'H',(byte)'E',(byte)'L',(byte)'L',(byte)'O'};
//	private byte[] nonce = new byte[]{0x07,0x05,0x06,0x07};
//	private final static byte CertC0=(byte)0x20;	//common cert
//	private final static byte SKC0=(byte)0x21;
//	private final static byte CertCA=(byte)0x22;	//CA
	private final static byte[] CertG= new byte[]{0x30, 0x48, 0x2, 0x41, 0x0,(byte) 0xb3, 0x2a, 0x28, (byte)0x95,(byte) 0x94, (byte)0xd6, 0x7d, 0xc, 0x1c,(byte) 0xfb, 0x2c, (byte)0xea, 0xe, 0x2e, 0x3d, (byte)0x8d, (byte)0xd3,(byte) 0x82, 0x26, (byte)0xc0, 0x14, 0x35, 0x37,(byte) 0xbb, 0x21, 0x30, 0x77, 0x24, 0x6a, 0xc,(byte) 0xd3, (byte)0xb9, (byte)0x96, 0x78, 0x72, 0x5b, 0x4e, 0x38, 0x2a,(byte) 0xf1,(byte) 0xd8, 0x4a, 0x18, (byte)0xb6, (byte)0xeb, (byte)0xb8, (byte)0xb5, (byte)0xdc, (byte)0xb3, (byte)0xbe, 0x7a, (byte)0xdb, 0x78, 0x5e, 0x3, 0x70, 0x13, (byte)0xc9, 0x6, 0x49, 0x76, 0x7f, (byte)0xf3, 0x6d, 0x2, 0x3, 0x1, 0x0, 0x1};	//cert for gov timestam
//	private final static byte SKG=(byte)0x24;
//	private final static byte CertSP=(byte)0x25;	//cert in each domain
//	private final static byte SKsp=(byte)0x26;
//	private final static byte Ku=(byte)0x27;
//	private final static byte privKey=(byte)0x28;
//	private final static byte pubKey=(byte)0x29;
	private static RSAPublicKey pubKey;
	private static RSAPrivateKey privKey;
	private static KeyPair kp;
	private static byte[] nonce;
	
	
//	allocate all memory applet needs during its lifetime

	private IdentityCard() {
		/*
		 * During instantiation of the applet, all objects are created.
		 * In this example, this is the 'pin' object.
		 */
		pin = new OwnerPIN(PIN_TRY_LIMIT,PIN_SIZE);
		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, PIN_SIZE);
		/*
		 * This method registers the applet with the JCRE on the card.
		 */
		//create placeholder for personal information to be given per service provider
		//4086 from tutorial, might be too long for this javacard but might work in jcwde
		//info = new byte[4086];
		
		genKeyPair(); //initialize javacard keys
//		nonce = genNonceInstance((short)3); //simple nonce
		register();
	}

	
	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
			new IdentityCard();
		}
	
	/*
	 * If no tries are remaining, the applet refuses selection.
	 * The card can, therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining()==0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives. Processes incoming APDU
	 */
	public void process(APDU apdu) throws ISOException {
		//A reference to the buffer, where the APDU data is stored, is retrieved.
		byte[] buffer = apdu.getBuffer();
		//needed for looping when sending large arrays
		 short LC = apdu.getIncomingLength();
		
		//If the APDU selects the applet, no further processing is required.
		if(this.selectingApplet()){
			return;
		}
		//Check whether the indicated class of instructions is compatible with this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS]){
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case REQ_VALIDATION_INS:
			reqRevalidation(apdu);
			break;
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
		case GET_eGov_DATA:
			eGov_DATA(apdu);
			break;
		case GET_Health_DATA:
			HealthDATA(apdu);
			break;
		case GET_SN_DATA:
			SNDATA(apdu);
			break;
		case GET_def_DATA:
			defDATA(apdu);
			break;
		//placeholder for testing methods
		case GET_TS_DATA:
			TSDATA(apdu);
			break;
			
//		case GET_pubKey:
//			getPubKeyINS(apdu);
//			break;
//		generate a nonce of size 'n' for each run	
		case GEN_NONCE: 
			genNonce(apdu);
			break;
		case GET_Exponent:
			getExponent(apdu);
			break;
		case GET_Modulus:
			getModulus(apdu);
			break;	
				
//		//hard code
//		case SET_Data:
//			setData(apdu);
//			break;
//		//hard code
//		case Set_PIN:
//			setPin(apdu);
//			break;
		//default: genNonce(apdu);	
		//If no matching instructions are found it is indicated in the status word of the response.
		//This can be done by using this method. As an argument a short is given that indicates
		//the type of warning. There are several predefined warnings in the 'ISO7816' class.
		default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	/*
	 * This method is used to authenticate the owner of the card using a PIN code.
	 */
	private void validatePIN(APDU apdu){
		byte[] buffer = apdu.getBuffer();
		//The input data needs to be of length 'PIN_SIZE'.
		//Note that the byte values in the Lc and Le fields represent values between
		//0 and 255. Therefore, if a short representation is required, the following
		//code needs to be used: short Lc = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
		if(buffer[ISO7816.OFFSET_LC]==PIN_SIZE){
			//This method is used to copy the incoming data in the APDU buffer.
			apdu.setIncomingAndReceive();
			//Note that the incoming APDU data size may be bigger than the APDU buffer 
			//size and may, therefore, need to be read in portions by the applet. 
			//Most recent smart cards, however, have buffers that can contain the maximum
			//data size. This can be found in the smart card specifications.
			//If the buffer is not large enough, the following method can be used:
			//byte[] buffer = apdu.getBuffer();
			//short bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
			//Util.arrayCopy(buffer, START, storage, START, (short)5);
			//short readCount = apdu.setIncomingAndReceive();
			//short i = ISO7816.OFFSET_CDATA;
			//while ( bytesLeft > 0){
			//	Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, storage, i, readCount);
			//	bytesLeft -= readCount;
			//	i+=readCount;
			//	readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			//}
			if (pin.check(buffer, ISO7816.OFFSET_CDATA,PIN_SIZE)==false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		}
		//shouldn't indicate that it was not accepted because of size, keep matter unknown
//		else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		else ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	private void getExponent(APDU apdu) {
	    byte[] buffer = apdu.getBuffer();
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
            BigInteger rexp = publicKey.getPublicExponent();
            byte[] rexpo = rexp.toByteArray();
            if (rexpo[0] == 0) {
                byte[] tmp = new byte[rexpo.length - 1];
                System.arraycopy(rexpo, 1, tmp, 0, tmp.length);
                rexpo = tmp;
            }
    		apdu.setOutgoing();
    		apdu.setOutgoingLength((short)rexpo.length);
    		apdu.sendBytesLong(rexpo,(short)0,(short)rexpo.length);
		    }
		}

	private void getModulus(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			
			
            RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
			
            BigInteger rmod = publicKey.getModulus();
			
			
            byte[] rmodu = rmod.toByteArray();
            if (rmodu[0] == 0) {
                byte[] tmp = new byte[rmodu.length - 1];
                System.arraycopy(rmodu, 1, tmp, 0, tmp.length);
                rmodu = tmp;
            }
			
    		apdu.setOutgoing();
    		apdu.setOutgoingLength((short)rmodu.length);
    		apdu.sendBytesLong(rmodu,(short)0,(short)rmodu.length);
		    }
		}	
	//receive signed time from SP through Client; update card time if client time more recent 
		private void genNonce(APDU apdu){
			if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			else{
				//nonce  = new byte[20];
				//RandomData rand = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		        //rand.generateData(nonce, (short)0, (short)nonce.length);
		        //nonce = {'h','e','l','l','o'};
				
				byte[] alice = getSecureRand((short)5);
				byte[] bob = getSecureRand((short)5);
				
				byte[] ab = concat(alice, bob);
				
				apdu.setOutgoing();
				apdu.setOutgoingLength((short)ab.length);
				apdu.sendBytesLong(ab,(short)0,(short)ab.length);
			    }
			}
	
	//receive signed time from SP through Client; update card time if client time more recent 
	private boolean reqRevalidation(APDU apdu){
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			byte[] buffer = apdu.getBuffer();
			byte[] newBuff = new byte[11];   // contains currentTime   
			//read apdu time data sent from Client
			//verify time validity from G server through middleware 
			short srcOff = (short) 9;
			short destOff = (short) 0;
			short length = (short) 11;
			//currentTime =
			Util.arrayCopy(buffer, srcOff, newBuff, destOff, length);
			//within same year, for completeness, 
			if(lastValidationTime != null && Util.arrayCompare(lastValidationTime, (short)0, newBuff, (short)0, (short)4)==0){
				//check if within 24 hours, same day of year
				if((short)(lastValidationTime[4]-currentTime[4])>1&&(short)(lastValidationTime[5]+currentTime[5])<2){
				return true;
				}
			}
			else{
				return false;// not within 24 hours or same year or lastValidationTime is null
			}
		} return false;
	}

//card serial number-not real #
	private void getSerial(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)serial.length);
			apdu.sendBytesLong(serial,(short)0,(short)serial.length);
		}
	}
	
	//working in progress for all INS
//Gov data
	private void eGov_DATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)name.length);
			apdu.sendBytesLong(name,(short)0,(short)name.length);
		}
	}

//Health data
	private void HealthDATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)name.length);
			apdu.sendBytesLong(name,(short)0,(short)name.length);
		}
	}	
	
//Default data	
	private void defDATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)info.length);
			apdu.sendBytesLong(info,(short)0,(short)info.length);
		}
	}
	
//social network 
	private void SNDATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			//This sequence of three methods sends the data contained in
			//'identityFile' with offset '0' and length 'identityFile.length'
			//to the host application.
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)info.length);
			apdu.sendBytesLong(info,(short)0,(short)info.length);
		}
	}

//timeStamp
	private void TSDATA(APDU apdu){
		//If the pin is not validated, a response APDU with the
		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else{
			byte[] rg = getSecureRand((short)20);
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)rg.length);
			apdu.sendBytesLong(rg,(short)0,(short)rg.length);
		}
	}
	
//helper methods	
//	generate RSAPub keys
	public void genKeyPair(){
		KeyPairGenerator kpg;
		try {
			kpg = KeyPairGenerator.getInstance("RSA");
	        kpg.initialize(512);
	        kp = kpg.genKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	//concatenating two arrays in two steps, noting that current setup, ar1.length = 1
	private byte[] concat(byte[] ar1, byte[] ar2){
		byte[] ar = new byte[ar1.length + ar2.length];
		//step 1: copy bytes of first array into ar
		for(short i = 0; i < ar1.length; i ++){
			ar[i] = ar1[i];
		}
		//step 2: copy ar2 into remaining space in ar
//		Util.arrayCopy(ar, (short)ar1.length,ar2, (short)0, (short)ar.length);
		Util.arrayCopy(ar2, (short)0, ar, (short)ar1.length, (short)ar2.length);
		return ar;
	}
	
	// for a 20 byte challenge
	private byte[] getSecureRand(short n){
		SecureRandom random = new SecureRandom();
	    byte[] values = new byte[n];
	    random.nextBytes(values);
	    return values;
	}
	
	private byte[] getPseudoRand(short n){
		byte[] buf = new byte[n];
		RandomData rand = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
	    rand.generateData(buf, (short)0, (short)buf.length);
		 return buf;
	}
	
	
	
	
//	maybe for later if we have the time
//	//no need for now, hard coded in
//	//gov initially sets data
//	private void setData(APDU apdu){
//	    short dataOffset = apdu.getOffsetCdata();
//	    short bytes_left = (short) buffer[ISO.OFFSET_LC];
//		short readCount = apdu.setIncomingAndReceive();
//		while (bytes_left > 0) {
//		//{process received data in buffer}
//		bytes_left -= readCount;
//		//get more data
//		readCount = apdu.receiveBytes (ISO.OFFSET_CDDATA);
//		}	    
//		//verification via certificate of
//		apdu.setIncomingAndReceive();
//		apdu.receiveBytes(incomingData);
//	}
//
//	
//	//no need for now, it's done by the client
//	//owner of card sets pin
//	private void setPin(APDU apdu){
//		//If the pin is not validated, a response APDU with the
//		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
//		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
//		else{
//			apdu.setIncomingAndReceive();
//			apdu.receiveBytes(newPin);
//			// use: update(byte[] pin, short offset, byte length)
//			// to update pin object
//		}
//	}
	
}
