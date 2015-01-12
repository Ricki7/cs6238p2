import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

public class SDDR_Client {
	//Protocol variables
	public static final String[] SECURITY_FLAGS = new String[] {"CONFIDENTIAL", "INTEGRITY", "NONE"};
	public static final String[] PROPAGATION_FLAGS = new String[] {"TRUE", "FALSE"};
	public static final String[] ACCESS_RIGHTS = new String[] {"BOTH", "GET", "PUT"};
	
	//Crypto constants
	public static int AES_KEY_SIZE = 128;
	
	//Prints correct usage
	public static void usage(){
		System.out.println("\nSecure Distributed Document Repository (SDDR)");
		System.out.println("=============================================");
		System.out.println("Commands:");
		System.out.println("\tstart-session(hostname)\t\t\t\t\t- A new secure session is started with the server running at host hostname.");
		System.out.println("\tget(DocumentUID)\t\t\t\t\t- Request a document over the secure channel from the server.");
		System.out.println("\tput(DocumentUID, SecurityFlag)\t\t\t\t- Send a document to the server over the secure channel.");
		System.out.println("\tdelegate(DocumentUID, Client, Time, PropagationFlag, Access)\t- A delegation credential (e.g., signed token) is generated that allows an owner client to delegate rights (put, get or both) for a document to another client C for a time duration of T.");
		System.out.println("\tend-session()\t\t\t\t\t\t- Terminates the current session.");
		System.out.println();
	}
	
	//Encrypts byte string using provided key and return byte ciphertext 
	public static byte[] AsymEncrypt(byte[] plainText, Key key) throws Exception{
		Cipher AsymCipher = Cipher.getInstance("RSA");
		AsymCipher.init(Cipher.ENCRYPT_MODE, key);
		return AsymCipher.doFinal(plainText);
	}

	//Decrypts byte string using provided key and return byte plaintext
	public static byte[] AsymDecrypt(byte[] cipherText, Key key) throws Exception{
	    Cipher AsymCipher = Cipher.getInstance("RSA");
	    AsymCipher.init(Cipher.DECRYPT_MODE, key);
	    return AsymCipher.doFinal(cipherText);
	}

	//Decrypts or encrypts bytes based on cipher
	public static byte[] SymmetricCrypt(byte[] input, Cipher cipher) throws Exception{
	    byte[] output = new byte[cipher.getOutputSize(input.length)];
	    int len = cipher.update(input, 0, input.length, output, 0);
	    len += cipher.doFinal(output, len);
	    return output;
	}
	
	private static byte[] getHash(byte[] input) throws Exception{
		MessageDigest cript = MessageDigest.getInstance("SHA-1");
		cript.reset();
		cript.update(input);
		return cript.digest();
	}
	
	//Convert bytes to hex string
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] input) {
		if(input == null)
			return null;
	    char[] hexChars = new char[input.length * 2];
	    for ( int j = 0; j < input.length; j++ ) {
	        int v = input[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	//Generate signature using privatekey
	private static byte[] createSig(byte[] input, PrivateKey key){
	    byte[] signature = null;
	    try {
	        Signature s = Signature.getInstance("SHA1withRSA");
	        s.initSign(key);
	        s.update(input);
	        signature = s.sign();
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	    return signature;
	}
	
	//Verify signature
	private static boolean verifySig(byte[] input, byte[] signature, PublicKey key){
		boolean valid = false;
	    try {
	        Signature s = Signature.getInstance("SHA1withRSA");
	        s.initVerify(key);
	        s.update(input);
	        valid = s.verify(signature);
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	    return valid;
	}
	
	public static void main(String[] args) throws Exception{
		//initialize symmetric crypto variables
		Key key;
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(AES_KEY_SIZE);
		Cipher encCipher = Cipher.getInstance("AES/CTR/NoPadding");
		Cipher decCipher = Cipher.getInstance("AES/CTR/NoPadding");
		
		//initialize variables
		BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
		Socket socket = null;
		DataOutputStream socketOut = null;
		DataInputStream socketIn = null;
		boolean connected = false;
		boolean quit = false;
		boolean verbose = false;
		byte[] cipherText;
		String plainText;
   		ArrayList<CheckedOutFile> checkedOutFiles = new ArrayList<CheckedOutFile>();
	    
		//Select user
		System.out.printf("Username:");
		String username = inFromUser.readLine();
		
		//Get user password
		System.out.printf("Password:");
		String password = inFromUser.readLine();
		
		//Loop until user quits
		while(!quit){
			System.out.printf("SDDR>");
			String input = inFromUser.readLine();
			
			if(input != null){
				//Split user input based on parenthesis and comma
				String[] command = input.split("\\(|\\)|,");
				
				switch (command[0]) {
				case "start-session":
					//Verify user input
					if(command.length != 2){
						System.out.println("Invalid Arguments");
						break;
					} else if(connected){
						System.out.println("Already connected!");
						break;
					}
					//Connect to server on port 6789
					socket = new Socket(command[1], 6789);
					socketOut = new DataOutputStream(socket.getOutputStream());
					socketIn = new DataInputStream(socket.getInputStream());
					
					//Read in asymmetric keys
					FileInputStream fin = new FileInputStream(username + "_keystore.jks");
				    KeyStore keystore = KeyStore.getInstance("JKS");
				    keystore.load(fin, password.toCharArray());
				    final Key serverKey = keystore.getCertificate("server").getPublicKey();
				    final Key privateKey = keystore.getKey(username, password.toCharArray());
				    
				    //Send username
					cipherText = AsymEncrypt(username.getBytes(), serverKey);
					socketOut.writeInt(cipherText.length);
				    socketOut.write(cipherText);
				    
				    //Receive status message 
				    cipherText = new byte[socketIn.readInt()];
			   		socketIn.readFully(cipherText);
			   		plainText = new String(cipherText);
				    
				    if(plainText.equals("Success")){
					    //Generate session key, encrypt it w/ server key, and send
					    key = kgen.generateKey();
					    cipherText = AsymEncrypt(key.getEncoded(), serverKey);
					    socketOut.writeInt(cipherText.length);
					    socketOut.write(cipherText);
					    if(verbose)
					    	System.out.println("Sent Key: " + bytesToHex(key.getEncoded()));
					    
					    //Sign encrypted session key and send
					    byte[] sig = createSig(cipherText, (PrivateKey)privateKey);
					    socketOut.writeInt(sig.length);
					    socketOut.write(sig);
					    if(verbose)
					    	System.out.println("Sent Signature: " + bytesToHex(sig));
					    
					    //Encrypt session IV using public server key and send
					    cipherText = new byte[socketIn.readInt()];
				   		socketIn.readFully(cipherText);
				   		byte[] iv = AsymDecrypt(cipherText, privateKey);
				   		if(verbose)
				   			System.out.println("Received IV: " + bytesToHex(iv));
					    
				   		//Read in server signature
				   		sig = new byte[socketIn.readInt()];
				   		socketIn.readFully(sig);
				   		boolean valid = verifySig(cipherText, sig, (PublicKey)serverKey);
				   		if(verbose)
				   			System.out.println("Received Signature: " + bytesToHex(sig));
				   		
				   		if(valid){
				   			//Generate IV and symmetric key for session 
							encCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
						    decCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
						    
						    //Read in server acknowledgement
						    cipherText = new byte[socketIn.readInt()];
					   		socketIn.readFully(cipherText);
					   		plainText = new String(SymmetricCrypt(cipherText, decCipher));
					   		if(verbose)
					   			System.out.println(socket.getRemoteSocketAddress() + ": " + plainText);
					   		
					   		//Verify connection establishment and valid server signature
					   		if(plainText.equals("Success")){
					   			connected = true;
				   				System.out.println("Connection Established");
					   		}
				   		}
				   		
				   		if(!connected) {
				   			System.out.println("Connection Failed");
				   		}
			   		} else {
			   			System.out.println("Invalid Username");
			   		}
					break;
				case "get":
					//Ensure proper usage and user is connected
					if(command.length != 2){
						System.out.println("Invalid Arguments");
						break;
					}
					if(socket == null){
						System.out.println("No session established");
						break;
					}
					
					//send encrypted get command
					cipherText = SymmetricCrypt(input.getBytes(), encCipher);
				    socketOut.writeInt(cipherText.length);
				    socketOut.write(cipherText);
					System.out.println("Sent: " + input);
					
					//receive status command
					cipherText = new byte[socketIn.readInt()];
			   		socketIn.readFully(cipherText);
			   		plainText = new String(SymmetricCrypt(cipherText, decCipher));
								   		
			   		if(plainText.equals("Success") || plainText.equals("Invalid")){
						if(plainText.equals("Invalid")){
							System.out.println("WARNING: Invalid Signature - File appears to be tampered with.");	
						}
						//receive file based on command
				   		cipherText = new byte[socketIn.readInt()];
				   		socketIn.readFully(cipherText);
				   		byte[] fileBytes = SymmetricCrypt(cipherText, decCipher);
				   		
				   		//receive slevel
						cipherText = new byte[socketIn.readInt()];
				   		socketIn.readFully(cipherText);
				   		plainText = new String(SymmetricCrypt(cipherText, decCipher));
				   		int slevel = Integer.parseInt(plainText);
				   		
						//Save file
				   		File dir = new File(username);
				   		dir.mkdir();
						FileOutputStream out = new FileOutputStream(username + '/' + command[1]);
						out.write(fileBytes);
						out.close();
						
						int checked = 0;
						for(CheckedOutFile c:checkedOutFiles){
							if(c.fileName.equals(command[1])){ //already checked out in this session
								checked = 1;
							}
						}
						
						if(checked == 0){
							byte[] hash = getHash(fileBytes);
							CheckedOutFile cof = new CheckedOutFile(command[1], hash, slevel);
							checkedOutFiles.add(cof);
						}

						System.out.println("File downloaded successfully");
			   		} else {
			   			System.out.println("File download failed");
			   		}
					break;
				case "put":
					//Ensure proper usage and user is connected
					if(command.length != 3){
						System.out.println("Invalid Number of Arguments");
						break;
					}
					if(!Arrays.asList(SECURITY_FLAGS).contains(command[2].toUpperCase().trim())){
						System.out.println("Invalid Security Flag. Acceptable values are 'confidential' or 'integrity' or 'none'");
						break;
					}
					if(socket == null){
						System.out.println("No session established");
						break;
					}
				    
				    //read-in file
					plainText = "";
				    try{
					    Path p = FileSystems.getDefault().getPath(username, command[1]);
				        byte [] fileData = Files.readAllBytes(p);
				 
				        //send encrypted put command
						cipherText = SymmetricCrypt(input.getBytes(), encCipher);
					    socketOut.writeInt(cipherText.length);
					    socketOut.write(cipherText);
					    if(verbose)
					    	System.out.println("Sent: " + input);
					    
					    //receive status command
					    cipherText = new byte[socketIn.readInt()];
				   		socketIn.readFully(cipherText);
				   		plainText = new String(SymmetricCrypt(cipherText, decCipher));
				   		if(verbose)
				   			System.out.println(socket.getRemoteSocketAddress() + ": " + plainText);
				   		
				   		if(plainText.equals("Success")){
							//send file
					        cipherText = SymmetricCrypt(fileData, encCipher);
						    socketOut.writeInt(cipherText.length);
						    socketOut.write(cipherText);
					        
							//receive status command
						    cipherText = new byte[socketIn.readInt()];
					   		socketIn.readFully(cipherText);
					   		plainText = new String(SymmetricCrypt(cipherText, decCipher));
					   		if(verbose)
					   			System.out.println(socket.getRemoteSocketAddress() + ": " + plainText);
				   		}
				    } catch (IOException e){
				    	System.out.println("ERROR: Failed to open file");
				    }
					    
				    if(plainText.equals("Success")){
		   				System.out.println("New file uploaded successfully");
			   		} else if(plainText.equals("Updated")){
			   			System.out.println("File updated successfully");
			   		} else {
			   			System.out.println("File upload failed");
			   		}
					break;
				case "delegate":
					//Ensure proper usage and user is connected
					if(socket == null){
						System.out.println("No session established");
						break;
					}
					if(command.length != 6){
						System.out.println("Invalid Number of Arguments");
						break;
					}
					if(!Arrays.asList(PROPAGATION_FLAGS).contains(command[4].toUpperCase().trim())){
						System.out.println("Invalid Propagation Flag. Must be 'true' or 'false'");
						break;
					}
					if(!Arrays.asList(ACCESS_RIGHTS).contains(command[5].toUpperCase().trim())){
						System.out.println("Invalid Right. Must be 'get', 'put', or 'both'");
						break;
					}
					
					//Send encrypted command 
					cipherText = SymmetricCrypt(input.getBytes(), encCipher);
				    socketOut.writeInt(cipherText.length);
				    socketOut.write(cipherText);
				    if(verbose)
				    	System.out.println("Sent: " + input);
					
					//receive status command
					cipherText = new byte[socketIn.readInt()];
			   		socketIn.readFully(cipherText);
			   		plainText = new String(SymmetricCrypt(cipherText, decCipher));
			   		
			   		if(plainText.equals("Success")){
			   			System.out.println("Delegation successful");
			   		} else if(plainText.equals("Denied")){
			   			System.out.println("ERROR Access Denied");
			   		} else {
			   			System.out.println("ERROR No such file");
			   		}
					break;
				case "quit":
				case "exit":
				case "end-session":
					if(socket != null){
						//loop through sha1 hashes for modification
						Path path;
						byte[] fileBytes;
						int number_to_update = 0;
						//for count number_to_update
						for(CheckedOutFile cof:checkedOutFiles){
					        path = Paths.get(username + '/' + cof.fileName);
					        fileBytes = Files.readAllBytes(path);
							byte[] hash_now = getHash(fileBytes);
							if(!Arrays.equals(hash_now, cof.hash)){
								number_to_update += 1;
							}
						}
						
						//Send encrypted command 
						cipherText = SymmetricCrypt("end-session".getBytes(), encCipher);
					    socketOut.writeInt(cipherText.length);
					    socketOut.write(cipherText);
						System.out.println("Sent: " + input);
						
						//send number of files that need to update
						cipherText = SymmetricCrypt(Integer.toString(number_to_update).getBytes(), encCipher);
					    socketOut.writeInt(cipherText.length);
					    socketOut.write(cipherText);
						
						//update module
						for(CheckedOutFile cof:checkedOutFiles){
					        path = Paths.get(username + '/' + cof.fileName);
					        fileBytes = Files.readAllBytes(path);
							byte[] hash_now = getHash(fileBytes);
							if(!Arrays.equals(hash_now, cof.hash)){
								//start to update this file
								plainText = "";
								Path p = FileSystems.getDefault().getPath(username, cof.fileName);
							    byte [] fileData = Files.readAllBytes(p);
								
								//send file
						        cipherText = SymmetricCrypt(fileData, encCipher);
							    socketOut.writeInt(cipherText.length);
							    socketOut.write(cipherText);
							    
								//send file name
						        cipherText = SymmetricCrypt(cof.fileName.getBytes(), encCipher);
							    socketOut.writeInt(cipherText.length);
							    socketOut.write(cipherText);
								
								//send securityLevel
							    cipherText = SymmetricCrypt(Integer.toString(cof.securityLevel).getBytes(), encCipher);
							    socketOut.writeInt(cipherText.length);
							    socketOut.write(cipherText);
							    
								System.out.println(cof.fileName+" is changed and updated accordingly.");
							}
						}
					    
						socket.close();
						connected = false;
						System.out.println("Session Ended");
						socket = null;
					} else {
						System.out.println("No session established");
					}
					if(command[0].equals("quit") || command[0].equals("exit")){
						quit = true;
						System.out.println("Bye!");
					}
						
					break;
				case "help":
					usage();
					break;
				case "verbose":
					verbose = !verbose;
					System.out.println("Verbose set to " + verbose);
					break;
				case "":
					break;
				case "shutdown":
					if(socket == null){
						System.out.println("No session established");
						break;
					}
					//Send encrypted command 
					cipherText = SymmetricCrypt(input.getBytes(), encCipher);
				    socketOut.writeInt(cipherText.length);
				    socketOut.write(cipherText);
					System.out.println("Sent: " + input);
					socket.close();
					connected = false;
					socket = null;
					break;
				default:
					System.out.println("Unknown command");
					break;
				}
			}
		}
	}
}
