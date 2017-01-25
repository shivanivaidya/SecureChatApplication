import java.io.*;
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;

import org.apache.commons.codec.binary.Hex;

public class Secure {
	static Cipher PublicKeyCipher;
	byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // Initialization Vector
    IvParameterSpec ivspec = new IvParameterSpec(iv);
	
	public Secure() {
		try {
			PublicKeyCipher = Cipher.getInstance("RSA");
		}
		catch(Exception e) {
			e.printStackTrace();
			System.exit(0); // Exits the program.
		}
	}
	
	public KeyPair generateKeyPair() throws Exception {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			
			KeyPair pair = keyGen.generateKeyPair();
			return pair;
	}
	
	public String generateHash(String str) throws IOException, NoSuchAlgorithmException, 
												  InvalidKeySpecException, SignatureException, 
												  InvalidKeyException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(str.getBytes("UTF-8"));
		String hash = new String(md.digest());
		return hash;
	}
	
	public long generateNonce() {
		SecureRandom sr = new SecureRandom();
		long nonce = sr.nextLong();
		return nonce;
	}
	
	public static Key generateAESKey() throws Exception { // Generates the AES Key. 
		byte[] encodedAES;
		SecretKeySpec AESKey;
		
		KeyGenerator g = KeyGenerator.getInstance("AES");
		g.init(256);
		SecretKey key = g.generateKey();
		encodedAES = key.getEncoded();
		AESKey = new SecretKeySpec(encodedAES, "AES");
		return AESKey;
	}
	
	public String encryptText(String in, Key key) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, ivspec);
		byte[] encrypted = blockCipher(in.getBytes("UTF-8"), "secret", Cipher.ENCRYPT_MODE, cipher);
	    char[] encryptedTranspherable = Hex.encodeHex(encrypted);
		return new String(encryptedTranspherable);
	}
	
	public String decryptText(String in, Key key) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, ivspec);
		int paddingNeeded = 16 - (Hex.decodeHex(in.toCharArray()).length % 16);
		byte[] decrypted = blockCipher(Hex.decodeHex(in.toCharArray()), "secret", Cipher.DECRYPT_MODE, cipher);
		return new String(decrypted,"UTF-8");
	}
	
	public String encData(String plaintext, Key PK)throws Exception {
		byte[] k = PK.getEncoded();
		byte[] data = plaintext.getBytes("UTF-8");
		
		X509EncodedKeySpec Xkey = new X509EncodedKeySpec(k);
		KeyFactory factory = KeyFactory.getInstance("RSA");
		PublicKey pk = factory.generatePublic(Xkey);
		
		PublicKeyCipher.init(Cipher.ENCRYPT_MODE, pk);
		byte[] encrypted = blockCipher(data, "public", Cipher.ENCRYPT_MODE, PublicKeyCipher);

		char[] enc = Hex.encodeHex(encrypted);
		return new String(enc);
	}
	
	public static String decData(String data, Key PK) throws Exception {		
		Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.DECRYPT_MODE, PK);
	    byte[] decrypted = blockCipher(Hex.decodeHex(data.toCharArray()), "private", Cipher.DECRYPT_MODE, cipher);
	    
	    return new String(decrypted,"UTF-8");
	}
	
	private static byte[] blockCipher(byte[] bytes, String type, int mode, Cipher cipher) throws IllegalBlockSizeException, 
																								 BadPaddingException, 
																								 UnsupportedEncodingException {
		// string initialize 2 buffers.
		// scrambled will hold intermediate results
		byte[] scrambled = new byte[0];
		int keyLength = 1024;
		// toReturn will hold the total result
		byte[] toReturn = new byte[0];
		// if we encrypt we use 100 byte long blocks. Decryption requires 128 byte long blocks (because of RSA)
		int length = (mode == Cipher.ENCRYPT_MODE) ? (keyLength / 8 ) - 11 : (keyLength / 8 );
		if(type.equals("secret")) {
			length = 256;
		}
		// another buffer. this one will hold the bytes that have to be modified in this step
		byte[] buffer = new byte[(bytes.length > length ? length : bytes.length)];

		for (int i=0; i< bytes.length; i++) {
			// if we filled our buffer array we have our block ready for de- or encryption
			if ((i > 0) && (i % length == 0)){
				//execute the operation
				scrambled = cipher.doFinal(buffer);
				// add the result to our total result.
				toReturn = append(toReturn,scrambled);
				// here we calculate the length of the next buffer required
				int newlength = length;

				// if newlength would be longer than remaining bytes in the bytes array we shorten it.
				if (i + length > bytes.length) {
					newlength = bytes.length - i;
				}
				// clean the buffer array
				buffer = new byte[newlength];
			}
			// copy byte into our buffer.
			buffer[i%length] = bytes[i];
		}

		// this step is needed if we had a trailing buffer. should only happen when encrypting.
		// example: we encrypt 110 bytes. 100 bytes per run means we "forgot" the last 10 bytes. they are in the buffer array
		scrambled = cipher.doFinal(buffer);

		// final step before we can return the modified data.
		toReturn = append(toReturn,scrambled);

		return toReturn;
	}
	
	private static byte[] append(byte[] prefix, byte[] suffix) {
		byte[] toReturn = new byte[prefix.length + suffix.length];
		for(int i=0; i< prefix.length; i++) {
			toReturn[i] = prefix[i];
		}
		for(int i=0; i< suffix.length; i++) {
			toReturn[i+prefix.length] = suffix[i];
		}
		return toReturn;
	}

	public static byte[] generateSessionID() throws Exception {
		SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
		//generate a random number
	    String randomNum = new Integer(prng.nextInt()).toString();
	    //get its digest
	    MessageDigest sha = MessageDigest.getInstance("SHA-1");
	    byte[] result =  sha.digest(randomNum.getBytes("UTF-8"));
	    return result;
	}
}