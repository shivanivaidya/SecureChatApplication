import java.io.Serializable;
import java.net.InetAddress;
import java.security.PublicKey;

import javax.crypto.SecretKey;

class Client implements Serializable { // The objects of this class are stored in the arraylist to maintain the details of the clients.
	private static final long serialVersionUID = 7842366454992399100L;
	private InetAddress ip; // Stores client ip address
	private int portNo; // Stores client port no
	private String username; // Stores client Username
	private String passwordHash; // Stores password hash
	private PublicKey clientPublicKey; // Stores the temporary(for that particular session) public key for the client
	private SecretKey aesKey; // Stores the shared key 
	
	public Client() { // Default constructor
		this.ip = null;
		this.portNo = 0;
		this.username = "";
		this.passwordHash = "";
		this.clientPublicKey = null;
		this.aesKey = null;
	}
		
	public Client(InetAddress ip, int portNo, String username, String passwordHash, SecretKey aesKey ) { // Parameterized constructor.
		this.ip = ip;
		this.portNo = portNo;
		this.username = username;
		this.passwordHash = passwordHash;
		this.aesKey = aesKey;
	}
		
	public Client(InetAddress ip, String username, PublicKey clientPublicKey ) { // Parameterized constructor.
		this.ip = ip;
		this.username = username;
		this.clientPublicKey = clientPublicKey;
	}
	
	// Setters
	
	public void setIp(InetAddress ip) {
		this.ip = ip;
	}	
	
	public void setPortNo(int portNo) {
		this.portNo = portNo;
	}
	
	public void setUsername(String username) {
		this.username = username;
	}
	
	public void setPasswordHash(String passwordHash) {
		this.passwordHash = passwordHash;
	}
	
	public void setClientPublicKey(PublicKey key) {
		this.clientPublicKey = key;
	}
	
	public void setAesKey(SecretKey aesKey) {
		this.aesKey = aesKey;
	}
	
	// Getters
	
	public InetAddress getIp() {
		return this.ip;
	}	
	
	public int getPortNo() {
		return this.portNo;
	}
	
	public String getUsername() {
		return this.username;
	}
	
	public String getPasswordHash() {
		return this.passwordHash;
	}
	
	public PublicKey getClientPublicKey() {
		return this.clientPublicKey;
	}
	
	public SecretKey getAesKey() {
		return this.aesKey;
	}	
}
	