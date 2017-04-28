package be.msec.smartcard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class IdentityCard extends Applet {
//	CLA code in CommandAPDU header
	private final static byte IDENTITY_CARD_CLA =(byte)0x80;
	
//	INS codes
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_SERIAL_INS = 0x24;
	
	private final static byte PIN_TRY_LIMIT =(byte)0x03;
	private final static byte PIN_SIZE =(byte)0x04;
		
	//INS codes for different SPs
	private final static byte GET_eGov_DATA=(byte)0x05;
	private final static byte GET_Health_DATA=(byte)0x06;	
	private final static byte GET_SN_DATA=(byte)0x07;
	private final static byte GET_def_DATA=(byte)0x08;
	//	timestamp implementation to be discussed
	//private final static byte GET_TS_DATA=(byte)0x09;
	
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	
//	instance variables declaration
	private byte[] serial = new byte[]{0x30, 0x35, 0x37, 0x36, 0x39, 0x30, 0x31, 0x05};
	private OwnerPIN pin;
	private byte[] buffer;
	//individuals identified by a service-specific pseudonym
	private byte[] nym_Gov = new byte[]{0x11}; // to have something to test data saving on javacard
	private byte[] nym_Health = new byte[]{0x12}; // to have something to test data saving on javacard
	private byte[] nym_SN = new byte[]{0x13}; // to have something to test data saving on javacard
	private byte[] nym_def = new byte[]{0x14}; // to have something to test data saving on javacard
	
	private byte[] name;
	private byte[] address;
	private byte[] country;
	private byte[] birthdate;
	private byte[] age;
	private byte[] gender;
	private byte[] picture;
	private byte[] bloodType;
	
	private final static byte CertC0=(byte)0x20;	//common cert
	private final static byte SKC0=(byte)0x21;
	private final static byte CertCA=(byte)0x22;	//CA
	private final static byte CertG=(byte)0x23;	//cert for gov timestam
	private final static byte SKG=(byte)0x24;
	private final static byte CertSP=(byte)0x25;	//cert in each domain
	private final static byte SKsp=(byte)0x26;
	private final static byte Ku=(byte)0x27;
	private final static byte PKG=(byte)0x28;

	
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
		register();
	}

////	constructor for each SP, byte array content
//	private IdentityCard(byte[] name;  byte[] address; byte[] country;) {
//		/*
//		 * During instantiation of the applet, all objects are created.
//		 * In this example, this is the 'pin' object.
//		 */
//		pin = new OwnerPIN(PIN_TRY_LIMIT,PIN_SIZE);
//		pin.update(new byte[]{0x01,0x02,0x03,0x04},(short) 0, PIN_SIZE);
//		/*
//		 * This method registers the applet with the JCRE on the card.
//		 */
//		register();
//	}
	
	
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
		//Receives data from buffer. Here we can have our own protocol
		byte[] buffer = apdu.getBuffer();
		
		//If the APDU selects the applet, no further processing is required.
		if(this.selectingApplet())
		
		//Check whether the indicated class of instructions is compatible with this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//A switch statement is used to select a method depending on the instruction
		switch(buffer[ISO7816.OFFSET_INS]){
		
		// suggest moving this outside 'switch' as a stand-alone elevated requirement for processing requests
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
		
//		to be coded 
		case GET_eGov_DATA:
			getGovData(apdu);
			break;

		case GET_Health_DATA:
			getHealthData(apdu);
			break;
			
		case GET_SN_DATA:
			getSNData(apdu);
			break;
			

		case GET_def_DATA:
			getdefData(apdu);
			break;

//			timestamp implementation to be discussed
//		case GET_TS_DATA:
//			getTSData(apdu);
//			break;
			
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
			//
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
	
	/*
	 * This method checks whether the user is authenticated and sends
	 * the identity file.
	 */
	
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
	
//		working in progress for all INS
//	private byte[]  getGovGET_eGov_DATA(APDU apdu){
//		//If the pin is not validated, a response APDU with the
//		//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
//		if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
//		else{
//			//This sequence of three methods sends the data contained in
//			//'identityFile' with offset '0' and length 'identityFile.length'
//			//to the host application.
//
//			
//		}
//	}
	
	// time should be gotten from timestamp server
//		private void getTime(APDU apdu){
//			//If the pin is not validated, a response APDU with the
//			//'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
//			if(!pin.isValidated())ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
//			else{
//			//return local time
//			LocalDateTime ldt = new LocalDateTime();
////			return ldt.getSecond();
//			Calendar cal = Calendar.getInstance();
//	        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
////	        return sdf.format(cal.getTime());
//	        // Get the current date and time
////	        LocalDateTime currentTime = LocalDateTime.now();
////	        return currentTime;
//;		}
//	}
}
