import java.io.*; 
import java.net.*; 
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.logging.Level;

import javax.crypto.SecretKey;
import javax.crypto.spec.*;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
 
class ChatServer implements Runnable, Serializable {
	// Stores the port number on which the server will be listening for connections.
	static int portno;
	// To count the number of threads created 
	static int count = 0; 
	// Stores server's public key to file
	static File ServerPublicKey = new File("ServerPublicKey"); 
	// Stores server's private key to file
	static File ServerPrivateKey = new File("ServerPrivateKey"); 
	static Base64 decode = new Base64();
	Socket csoc;
	// Object of Secure class
	Secure sec = new Secure();
	DataOutputStream dso;
	SecretKeySpec aesKey;
	DataInputStream in;
	PublicKey PubKeyC;
	
	// Stores the list of online clients
	static ArrayList<String> onlineUsers = new ArrayList<String>();  
	// Stores the list of registered clients	
	static HashMap<String,Client> registered = new HashMap<String,Client>(); 
	
	static PrivateKey pk;
	static PublicKey publicKeyLoaded;
	
	class AuthToken implements Serializable {
		private String uname;
		private PublicKey pkey;
		
		public AuthToken(String un, PublicKey pk)
		{
			uname = un;
			pkey = pk;
		}
	}
	
	// Parameterized constructor
	ChatServer(Socket cs) { 
		this.csoc = cs;
	}
		
	public static void main(String args[]) throws Exception {
		if (args.length != 1) { 
			/*If the port number is not entered or if more than one argument is entered,
			  prints the correct usage or format of the command and exits the program. */
			System.out.println("Usage: java ChatServer <Port Number>");
			System.exit(1);
		}
		
		try {
			File publicKey = new File("ServerPublicKey");
						
			byte[] encodedKey = new byte[(int)publicKey.length()];
			new FileInputStream(publicKey).read(encodedKey);
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			publicKeyLoaded = keyFactory.generatePublic(publicKeySpec);
			encodedKey=null;
						
			File privateKey = new File("ServerPrivateKey");
			encodedKey = new byte[(int)privateKey.length()];
			new FileInputStream(privateKey).read(encodedKey);
					   
			// create private key
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedKey);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			pk = kf.generatePrivate(privateKeySpec);
				
			/* The entered port is in String form. It is first converted to Integer and 
			   then stored in portno.*/	    
			portno = Integer.parseInt(args[0]); 
			ServerSocket ssoc = new ServerSocket(); 
			ssoc.setReuseAddress(true);
			ssoc.bind(new InetSocketAddress(portno));
			
			System.out.println ("Server Initialized...");
			
			// Accepts all incoming connections
			while(true) { 
				Socket csoc = ssoc.accept();				
				System.out.println(csoc.getRemoteSocketAddress());
				// Create a new thread for each connection
				Runnable r = new ChatServer(csoc);
				Thread thread = new Thread(r);
				// start thread
				thread.start(); 
			}
		}
		
		catch(Exception e) {
			e.printStackTrace();
			// Prints the correct usage or format of the command.
			System.out.println("Usage: java ChatServer <Port Number>"); 
			// Exits the program.
			System.exit(0); 
        }
	}
	
	@SuppressWarnings("unchecked")
	public void run() {
		try {
			in = new DataInputStream(csoc.getInputStream());

			while(true) {
				String incoming = in.readUTF();
				System.out.println("Accepted action number " + ++count);
				
				if(incoming.startsWith("REGISTRATION")) {
					registration(incoming, in);
				}
				
				if(incoming.startsWith("LOGIN")) {
					login(incoming, in);
				}
				
				if(incoming.startsWith("LIST_ONLINE_USERS_1")) {
					online(incoming, in);
				}
				
				if(incoming.startsWith("MESSAGE_REQUEST_1")) {
					message_request(incoming, in);
				}
				
				if(incoming.startsWith("logout")) {
					String username = incoming.split("\t")[1];
					logout(incoming, in, username);
					System.out.println("User Logged out");
					Thread.currentThread().interrupt();
					return;
				}
				
				if(incoming.startsWith("exit")) {
					String username = incoming.split("\t")[1];
					exitProgram(incoming, in, username);
					System.out.println("User Logged out");
					System.out.println("Bye!!");
					Thread.currentThread().interrupt();
					return;
				}
			}
		}
		
		catch(Exception e) {
			e.printStackTrace();
			System.exit(0); // Exits the program.
		}
	}
	
	private void exitProgram(String incoming, DataInputStream in2, String username) {
		registered.remove(username);
		onlineUsers.remove(username);
	}
	
	private void logout(String incoming, DataInputStream in2, String username) {
		onlineUsers.remove(username);
	}

	public void registration(String incoming, DataInputStream in) throws Exception {
		in = new DataInputStream(csoc.getInputStream());
		InetAddress ip = null;
		int portNo = 0;
		long nonce2 = 0L;
		
		if(incoming.startsWith("REGISTRATION_1")) {
			/*REGISTRATION MESSAGE1 RECEIVE (nonce1 encrypted by aes key and aes key 
			  encrypted by public key of server) */
			String[] tokenizerRM1 = incoming.split(":");
			
			String RM1T1 = tokenizerRM1[1];
			String RM1T2 = tokenizerRM1[2];
			
			ip = csoc.getInetAddress();
			
			byte[] aeskey = decode.decode(sec.decData(RM1T2, pk));
			aesKey = new SecretKeySpec(aeskey, "AES");
			String NONCE1 = sec.decryptText(RM1T1, aesKey);
			System.out.println(NONCE1);
			
			//REGISTRATION MESSAGE2 SEND (nonce1, nonce2 encrypted by aes)
			// Calls function to generate nonce
			nonce2 = sec.generateNonce(); 
			String NONCE2 = String.valueOf(nonce2);
			// Calls function that encrypts the NONCE with the AES Key
			String RM2P2 = sec.encryptText(NONCE2, aesKey); 
			
			dso = new DataOutputStream(csoc.getOutputStream());
			dso.writeUTF(NONCE1 +":"+ RM2P2);
		
			/* REGISTRATION MESSAGE3 RECEIVE (nonce2, username and password_hash 
			   encrypted by public key of server) */
			   
			String RM3 = in.readUTF();
			if(RM3.startsWith("REGISTRATION_3")) {
				String[] tokenizerRM3 = RM3.split(":");
				byte[] RM3T1 = decode.decode(tokenizerRM3[1]);
				String RM3T2 = tokenizerRM3[2];
							
				if(tokenizerRM3[0].trim().equals(NONCE2)) {
					System.out.println("Nonce2 match");
				}
				
				String RM3P2 = sec.decData(RM3T2, pk);
				String rm3p2 = new String(RM3P2);
				
				String[] tokenizerRM3P2 = rm3p2.split(":");
				String username = tokenizerRM3P2[0];
				String passwordHash = tokenizerRM3P2[1];
				
				//STORE USER DETAILS
				Client client = new Client(ip, portNo, username, passwordHash, aesKey);
				registered.put(username,client);			
			}
		}
	}
	
	public void login(String incoming, DataInputStream in) throws Exception {
		in = new DataInputStream(csoc.getInputStream());
		long nonce4 = 0L;
		if(incoming.startsWith("LOGIN_1")) {
			/* LOGIN MESSAGE1 RECEIVE (nonce3 and username and password hash and listening 
			   portNo and public key of a encrypted by aes key , aes key encrypted by public 
			   key of server) */
			
			String NONCE3 = sec.decryptText(incoming.split(":")[1], aesKey);
			String username = sec.decryptText(in.readUTF().split(":")[1], aesKey);
			String passwordHash = sec.decryptText(in.readUTF().split(":")[1], aesKey);
			int portNo = Integer.parseInt(sec.decryptText(in.readUTF().split(":")[1], aesKey));
			byte[] pk = decode.decode(sec.decryptText(in.readUTF().split(":")[1], aesKey));			
			
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PubKeyC = kf.generatePublic(new X509EncodedKeySpec(pk));
			
			//save A's public key to the registered A Client before
			if(registered.containsKey(username)) {
				Client c = registered.get(username);
				c.setClientPublicKey(PubKeyC);
				c.setPortNo(portNo);
				registered.put(username, c);
			}
			
			pk = null;			
			
			// LOGIN MESSAGE2 SEND (nonce3, nonce4 and username and sid encrypted by aes)
			// Calls function to generate nonce
			nonce4 = sec.generateNonce(); 
			// Converts nonce to byte array
			String NONCE4 = String.valueOf(nonce4); 
			
			// Generates SessionID
			byte[] sessionID = sec.generateSessionID();

			String str = NONCE4 + ":" + decode.encodeAsString(sessionID);
			
			// Calls function that encrypts the STR with the AES Key
			String LM2P2 = sec.encryptText(str, aesKey); 
			
			dso = new DataOutputStream(csoc.getOutputStream());
			dso.writeUTF(NONCE3+":"+ LM2P2);
			
			// LOGIN MESSAGE3 RECEIVE (nonce4)
			String LM3 = in.readUTF();
			
			if(LM3.startsWith("LOGIN_3")) {
				String[] tokenizerLM3 = LM3.split(":");
				
				if(tokenizerLM3[1].trim().equals(NONCE4)) {
					System.out.println("Nonce4 match\nUser logged in");
				}
				onlineUsers.add(username);
			}
		}		
	}
	
	public void online(String incoming, DataInputStream in) throws Exception {
		in = new DataInputStream(csoc.getInputStream());
		
		// LIST_ONLINE_USERS_1 RECEIVE (nonce5 and sid and username encrypted by aes)
		String TOMATO=incoming.split(":")[1];
		String[] tokenizerOM1 = sec.decryptText(TOMATO, aesKey).split(":");
		
		
		String username = tokenizerOM1[1];
		String sessionid = tokenizerOM1[2];
		
		// LIST_ONLINE_USERS_2 SEND (nonce5, list of online users encrypted by aes)
		
		String usernames = onlineUsers.get(0);
		for(int i = 1; i< onlineUsers.size(); i++) {
			usernames = usernames + "," + onlineUsers.get(i);
		}
		
		dso = new DataOutputStream(csoc.getOutputStream());
		dso.writeUTF(tokenizerOM1[0]+":"+ sec.encryptText(usernames , aesKey));
		System.out.println(tokenizerOM1[0]+":"+sec.encryptText(usernames , aesKey));
	}
	
	public void message_request(String incoming, DataInputStream in) throws Exception {
		in = new DataInputStream(csoc.getInputStream());
		
		// MESSAGE_REQUEST_1 RECEIVE (usernameA and usernameB and sid encrypted by aes key)
		
		String dMM1 = sec.decryptText(incoming.split(":")[1], aesKey);
		InetAddress toUserIP = null;
		int toUserPortNo = 0;
		SecretKey toAESKey = null;
		String[] tokenizerMM1 = dMM1.split(":");
		String fromUser = tokenizerMM1[0];
		String toUser = tokenizerMM1[1];
		String usid = new String(decode.decode(tokenizerMM1[2]), "UTF-8");
		PublicKey toKey = null;
		
		/* MESSAGE_REQUEST_2 SEND (ipB and portnoB and public key of B and Authentication 
		   token encrypted by aes, aes by public key of A) */
		if(registered.containsKey(toUser)) {
			Client c = registered.get(toUser);
			toAESKey = c.getAesKey();
			toUserPortNo = c.getPortNo();
			toUserIP = c.getIp();
			toKey = c.getClientPublicKey();
		}
		
		System.out.println("Send to: "+toUserIP);
		//Auth token: A's ip, A's pub key
		//telling B to accept only from A, and how to talk to him (A's pub)
		String eAT = fromUser+ ":" + decode.encodeAsString(PubKeyC.getEncoded());
		String encodedToPub = decode.encodeAsString(toKey.getEncoded());
		
		dso.writeUTF(sec.encryptText(toUserIP.getHostAddress()+":"+String.valueOf(toUserPortNo) , aesKey));
		dso.writeUTF(sec.encryptText(encodedToPub, aesKey));	
		//Encrypted with B's AES Key
		dso.writeUTF(sec.encryptText(eAT, toAESKey));	
	}
}