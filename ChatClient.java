import java.io.*; 
import java.net.*;
import java.util.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class ChatClient {
	static PublicKey ServerPublic; // Stores server's public key to file
	static String hostname = ""; // Stores hostname of server
	static int portno = 0; // Stores portno on which server is listening
	Socket soc; // Creates client socket
	String username; // Stores username
	String password_hash; // Stores password hash
	DataOutputStream dso; // To write byte array to output stream
	DataInputStream dsi;
	Secure sec = new Secure(); // Object of Secure class
	String authToken;
	DatagramSocket clientListeningSocket; // Stores Server Socket
	PublicKey clientPubKey;
	String status = ""; // Stores the status of the client
	Base64 encode = new Base64();
	byte[] SID = new byte[1024];
	PrivateKey PrivKeyA;
	PublicKey PubKeyA;

	Key AESKey;
	
	class AuthToken {
		private String uname;
		private PublicKey pkey;
		public AuthToken(String un, PublicKey pk)
		{
			uname = un;
			pkey = pk;
		}
	}
	
	public static void main(String[] args) throws Exception { // Main method
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); // To take user input
		ChatClient chatClient = new ChatClient();
		File publicKey = new File("ServerPublicKey");

		byte[] encodedKey = new byte[(int)publicKey.length()];
		new FileInputStream(publicKey).read(encodedKey);
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		ServerPublic = keyFactory.generatePublic(publicKeySpec);
		encodedKey=null;
		
		if (args.length != 2) {
		    /* If the hostname or port number is not entered or if more than two 
			   arguments are entered, this method prints the correct usage or format 
			   of the command and exits the program. */
			System.out.println("Usage: java ChatClient <Hostname or IP address> <Port Number>");
			System.exit(1);
		}
		
		try {
			int ch =0; // Stores user choice in the menu
			hostname = args[0]; 
			portno = Integer.parseInt(args[1]);
			
			System.out.println("\nWELCOME TO SECURE CHAT APPLICATION!");
			do {
				System.out.println("\nENTER A NUMBER TO SELECT OPTION:");
				System.out.println("1: REGISTER.");
				System.out.println("2: LOGIN.");
				System.out.println("3: VIEW ONLINE USERS.");
				System.out.println("4: SEND MESSAGE");
				System.out.println("5: LOGOUT.");
				System.out.println("6: EXIT.\n");
			
				ch = Integer.parseInt(br.readLine()); // Reads user choice
			
				switch(ch) {
					case 1: chatClient.register();
							break;
					case 2: chatClient.login();
							break;
					case 3: chatClient.online();
							break;
					case 4: chatClient.message_request();
							break;
					case 5: chatClient.logout();
							System.out.println("\nYOU HAVE BEEN LOGGED OUT.");
							break;
					case 6: chatClient.exitProgram();
							System.exit(0);
					default: System.out.println("\nINVALID CHOICE");
							 break;
				}
			} while(ch != 6);			
		}
		catch(Exception e) {
			e.printStackTrace();
			// Prints the correct usage or format of the command.
			System.out.println("Usage: java ChatClient <Hostname or IP address> <Port Number>"); 
			System.exit(0); // Exits the program.
        }
	}
	
	private void logout() throws IOException {
		dso.writeUTF("logout" + "\t" + username);
	}
	
	private void exitProgram() throws IOException {
		dso.writeUTF("exit" + "\t" + username);
	}
	
	//THREAD ACCESSED Method
	protected void clientListener(int portNo) throws Exception {
		clientListeningSocket = new DatagramSocket(portNo);
		while(true) {
			//buffer to hold the incoming message
			byte[] inbuf = new byte[4095];
			//receive the packet
			DatagramPacket incomingPacket = new DatagramPacket(inbuf, inbuf.length);
			clientListeningSocket.receive(incomingPacket);
			String received = new String(inbuf, 0, incomingPacket.getLength());
			
			String msg = sec.decData(received, PrivKeyA);
			if(msg.split(":")[0].equals("firstTime")) {
				String authToken = sec.decryptText(msg.split(":")[1], AESKey);
				String from = authToken.split(":")[0];
				byte[] receiverPubKey = encode.decode(authToken.split(":")[1]);
				System.out.println("MESSAGE FROM "+from + ":");
				//get other users public key
		
				X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(receiverPubKey);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				clientPubKey = keyFactory.generatePublic(publicKeySpec);
			}
			else {
				System.out.println(msg.split(":")[1] + "\n");
			}
		}
	}

	public void register() throws Exception {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); // To take user input
		status = "INPUT_USER_DETAILS";
		int flag = 0; // To check if the 2 passwords match
		String password; // Stores password
		do {
			System.out.println("\nENTER USERNAME:");
			username = br.readLine();
						
			System.out.println("\nENTER PASSWORD:");
			System.out.println("\n* YOUR PASSWORD SHOULD BE MINIMUM 8 CHARACTERS LONG, \n* SHOULD " +
			"CONSIST OF AT LEAST ONE UPPERCASE AND ONE LOWERCASE CHARACTER, " + 
			"\n* SHOULD CONSIST OF AT LEAST ONE DIGIT AND ONE SPECIAL CHARACTER. " +
			"\n* YOUR PASSWORD SHOULD NOT CONTAIN THE USERNAME IN ANY FORM.\n");
							
			password = br.readLine();
			int u =0, l = 0, n = 0, s = 0; // Uppercase, Lowercase, Digit, Special character
						
			for(int i =0; i < password.length(); i++) { // Check password is valid or not
				char pch = password.charAt(i); // Extracts character at ith position
				if(Character.isUpperCase(pch)) {
					u++;
				}
				else if(Character.isLowerCase(pch)) {
					l++;
				}
				else if(Character.isDigit(pch)) {
					n++;
				}
				else if(!Character.isDigit(pch) && !Character.isLetter(pch) && !Character.isSpaceChar(pch)) {
					s++;
				}
				else {
					System.out.println("\nILLEGAL CHARACTER IN PASSWORD.");
					break;
				}
			}
							
			if( u == 0 || l == 0 || n == 0 || s == 0) {
				System.out.println("\nINVALID PASSWORD. RETRY.");
				continue;
			}
			else {
				System.out.println("\nCONFIRM PASSWORD:");
				String cpassword = br.readLine(); // Stores the confirm password string
							
				if (!cpassword.equals(password)) { // Checks if both passwords match 
					System.out.println("\nPASSWORDS DO NOT MATCH. RETRY.");
					continue;
				}
				else
				flag = 1;
			}
		} while(flag != 1);
		
		password_hash = sec.generateHash(password); // Calls function to generate password hash
				
		soc = new Socket(hostname, portno);		// Creates socket
		dso = new DataOutputStream(soc.getOutputStream());
		dsi = new DataInputStream(soc.getInputStream());
		
		//REGISTRATION MESSAGE1 SEND (nonce1 encrypted by aes key and aes key encrypted by public key of server)
		long nonce1 = sec.generateNonce(); // Calls function to generate nonce
		String NONCE1 = String.valueOf(nonce1);
		
		AESKey = sec.generateAESKey(); // Calls Function to generate AES Key
		byte[] encodedAES = AESKey.getEncoded(); // Converts AES Key to byte array
		String AES = encode.encodeToString(encodedAES);
		String RM1P1 = sec.encryptText(NONCE1, AESKey); // Calls function that encrypts the NONCE with the AES Key
		String RM1P2 = sec.encData(AES, ServerPublic); //Calls function that encrypts AES key with Servers Public Key
		dso.writeUTF("REGISTRATION_1:" + RM1P1 +":"+ RM1P2);
		status = "R_MESSAGE1_SENT";
		
		//REGISTRATION MESSAGE2 RECEIVE (nonce1, nonce2 encrypted by aes)
		status = "R_MESSAGE2_RECV";
		String RM2 = dsi.readUTF();
		String[] tokenizerRM2 = RM2.split(":");
		String RM2T2 = tokenizerRM2[1];
		
		if(tokenizerRM2[0].trim().equals(NONCE1)) {
			System.out.println("\nREGISTRATION COMPLETE."); 
		}
		
		String NONCE2 = sec.decryptText(RM2T2, AESKey);
		
		//REGISTRATION MESSAGE3 SEND (nonce2, username and password_hash encrypted by public key of server)
		String user_pass = username + ":" + password_hash;
		
		byte[] rm3p2 = user_pass.getBytes("UTF-8");
		String Rm3p2 = new String(rm3p2);
		
		String RM3P2 = sec.encData(Rm3p2, ServerPublic);
		
		dso.writeUTF("REGISTRATION_3:" + NONCE2 +":"+ RM3P2);
		status = "R_MESSAGE3_SENT";	
	}
	
	public void login() throws Exception {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); // To take user input
		// Input Username
		System.out.println("\nENTER USERNAME:");
		String usrname = br.readLine();
		
		//Input password
		System.out.println("\nENTER PASSWORD:");
		String passwd = br.readLine();
		
		/* LOGIN MESSAGE1 SEND (nonce3 and username and password hash and public key of a encrypted 
		   by aes key , aes key encrypted by public key of server) */
		
		// Generate Nonce3
		long nonce3 = sec.generateNonce(); // Calls function to generate nonce
		String NONCE3 = String.valueOf(nonce3); // Converts nonce to byte array
		
		// Generate password hash
		String passwd_hash = sec.generateHash(passwd); // Calls function to generate password hash
		
		// Generate public and Private Key Pair for A
		KeyPair keyA = sec.generateKeyPair(); 
		PrivKeyA = keyA.getPrivate(); // Gets Private key of A
		PubKeyA = keyA.getPublic(); // Gets Public key of A
		byte[] KeyA = PubKeyA.getEncoded();
		//System.out.println(encode.encodeToString(KeyA));
				
		int portNo = 9000 + (int )(Math.random() * 500);
		
		// Encrypt the nonce3, username, password, portNo and public key of A with the AES key
		String str = NONCE3 + ":" + usrname + ":" + passwd_hash + ":" + portNo + ":" + encode.encodeToString(KeyA);
		byte[] STR = str.getBytes("UTF-8");
		
		String LM1P1 = sec.encryptText(str, AESKey); // Calls function that encrypts the message with the AES Key
		
		// Send Message 
		dso.writeUTF("LOGIN_1:" + sec.encryptText(NONCE3, AESKey));
		dso.writeUTF("LOGIN_1:" + sec.encryptText(usrname, AESKey));

		dso.writeUTF("LOGIN_1:" + sec.encryptText(passwd_hash, AESKey));
		dso.writeUTF("LOGIN_1:" + sec.encryptText(String.valueOf(portNo), AESKey));
		dso.writeUTF("LOGIN_1:" + sec.encryptText(encode.encodeToString(KeyA), AESKey));
		
		status = "L_MESSAGE1_SENT";
		
		// LOGIN MESSAGE2 RECEIVE (nonce3, nonce4 and username and sid encrypted by aes)
		
		status = "L_MESSAGE2_RECV";
		String LM2 = dsi.readUTF();
		String[] tokenizerLM2 = LM2.split(":");
		String LM2T2 = tokenizerLM2[1];
		
		if(tokenizerLM2[0].trim().equals(NONCE3)) {
			System.out.println("\nLOGGED IN SUCCESSFULLY!");
		}
		
		String lm2p2 = sec.decryptText(LM2T2, AESKey);
		
		String[] tokenizerLM2P2 = lm2p2.split(":");
		
		SID = encode.decode(tokenizerLM2P2[1]);
		
		// LOGIN MESSAGE3 SEND (nonce4)
		
		dso.writeUTF("LOGIN_3:" + tokenizerLM2P2[0]);
		//Login successful
		//Lets wait and listen for other Clients to connect
		//Start Client listener
		new Thread(
	            new Runnable() {
	                public void run() {
	                    try {
							clientListener(portNo);
						} catch (IOException e) {
							e.printStackTrace();
						} catch (Exception e) {
							e.printStackTrace();
						}
	                }
	            }
	        ).start();
	}
	
	public void online() throws Exception {
		/* REQUEST ONLINE USERS 1 SEND (nonce5 and sid and username encrypted by aes, 
		aes encrypted by public key of server) */
		
		//generate nonce
		String NONCE5 = String.valueOf(sec.generateNonce()); // Converts nonce to byte array
				
		// Encrypt the nonce5, username and SID with the AES key
		String str = NONCE5 + ":" + username + ":" + encode.encodeAsString(SID);
		String OM1P1 = sec.encryptText(str, AESKey); // Calls function that encrypts the message with the AES Key
		
		dso.writeUTF("LIST_ONLINE_USERS_1:" + OM1P1);
		
		// REQUEST ONLINE USERS 2 RECEIVE (nonce5, list of online users encrypted by aes)
		String OM2 = dsi.readUTF();
		String OM3 = sec.decryptText(OM2.split(":")[1], AESKey);
		String[] tokenizerOM2 = OM3.split(",");
		
		System.out.println("\nUSERS CURRENTLY ONLINE:");
		for(String in : tokenizerOM2){
			System.out.println(in.toString());
		}
	}
	
	public void message_request() throws Exception {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in)); // To take user input
		// MESSAGE REQUEST 1 SEND (usernameA and usernameB and sid encrypted by public key of server)
		System.out.println("\nENTER THE USERNAME YOU WISH TO COMMUNICATE WITH:");
		String user = br.readLine();
		String mm1 = username + ":" + user + ":" + encode.encodeAsString(SID);
			
		String eMM1 = sec.encryptText(mm1, AESKey);
		dso.writeUTF("MESSAGE_REQUEST_1:" + eMM1);
			
		/* MESSAGE REQUEST 2 RECEIVE (ipB and portnoB and public key of B and Authentication 
		   token encrypted by aes, aes by public key of A) */
			
		String[] toIpPort = sec.decryptText(dsi.readUTF(), AESKey).split(":");
		byte[] toPubKey = encode.decode(sec.decryptText(dsi.readUTF(), AESKey));
		authToken = dsi.readUTF();
			
		//get other users public key
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(toPubKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		clientPubKey = keyFactory.generatePublic(publicKeySpec);
			
		//Send speak request to other client
		String data = "firstTime"+":"+authToken;
		String encData = sec.encData(data, clientPubKey);
		//tell B your authtoken
		//so he has A's pub key
		sendClientMessage(InetAddress.getByName(toIpPort[0]), encData, Integer.parseInt(toIpPort[1]));
			
		System.out.println("\nENTER MESSAGE:");

		String msg = br.readLine();
		String Message =  sec.encData("conversation"+":"+msg, clientPubKey);
		sendClientMessage(InetAddress.getByName(toIpPort[0]), Message, Integer.parseInt(toIpPort[1]));
		System.out.println("\nMESSAGE SENT.");
	}
	
	private void sendClientMessage(InetAddress ip, String data, int port) throws NoSuchAlgorithmException, 
	                                                                             InvalidKeySpecException, 
	                                                                             IOException {		
		DatagramPacket packetToSend= new DatagramPacket(data.getBytes(), data.getBytes().length, ip, port);
		clientListeningSocket.send(packetToSend);
	}
	
	public String padRight(String s, int n) {
	     return String.format("%1$-" + n + "s", s);  
	}
}

			