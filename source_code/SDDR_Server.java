
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class SDDR_Server {
	//Protocol Constants
	public static final String[] SECURITY_FLAGS = new String[] {"NONE", "CONFIDENTIAL", "INTEGRITY"};
	public static final String[] ACCESS_RIGHTS = new String[] {"BOTH", "GET", "PUT"};
	
	//Cryptography Constants and files
	public static int AES_KEY_SIZE = 128;
	public static final String KEYSTORE = "server_keystore.jks";
	public static final String METADATAFILE = "meta_data_file";
	public static final String DELEGATIONFILE = "delegation_file";
	public static char[] KEYSTORE_PASSWORD = "server".toCharArray();
	
	//Encrypts byte string using provided key and return byte ciphertext
	private static byte[] AsymEncrypt(byte[] plainText, Key key) throws Exception{
		Cipher AsymCipher = Cipher.getInstance("RSA");
		AsymCipher.init(Cipher.ENCRYPT_MODE, key);
		return AsymCipher.doFinal(plainText);
	}
	
	//Decrypts byte string using provided key and return byte plaintext
	private static byte[] AsymDecrypt(byte[] cipherText, Key key) throws Exception{
	    Cipher AsymCipher = Cipher.getInstance("RSA");
	    AsymCipher.init(Cipher.DECRYPT_MODE, key);
	    return AsymCipher.doFinal(cipherText);
	}

	//Decrypts or encrypts bytes based on cipher
	private static byte[] SymmetricCrypt(byte[] input, Cipher cipher) throws Exception{
	    byte[] output = new byte[cipher.getOutputSize(input.length)];
	    int len = cipher.update(input, 0, input.length, output, 0);
	    len += cipher.doFinal(output, len);
	    return output;
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
	
	private static byte[] getHash(byte[] input) throws Exception{
		MessageDigest cript = MessageDigest.getInstance("SHA-1");
		cript.reset();
		cript.update(input);
		return cript.digest();
	}
	
	//Convert bytes to hex string
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	private static String bytesToHex(byte[] input) {
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
	
	public static void main(String[] args) throws Exception {
		//initialize symmetric crypto variables
        boolean quit = false;
        boolean connected = false;
        Cipher encCipher;
        byte[] uid;
        Metadata fileMetadata;
        byte[] fileBytes;
        byte[] cipherText;
        boolean hasAccess = false;
        
		try {
			encCipher = Cipher.getInstance("AES/CTR/NoPadding");
			Cipher decCipher = Cipher.getInstance("AES/CTR/NoPadding");
			Cipher encCipher2 = Cipher.getInstance("AES/CTR/NoPadding");
			Cipher decCipher2 = Cipher.getInstance("AES/CTR/NoPadding");
			
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			
			//Read in asymmetric keys
	   		FileInputStream fin = new FileInputStream(KEYSTORE);
		    KeyStore keystore = KeyStore.getInstance("JKS");
		    keystore.load(fin, KEYSTORE_PASSWORD);
		    final Key privateKey = keystore.getKey("server", "server".toCharArray());
		    final Key publicKey = keystore.getCertificate("server").getPublicKey();
	        
		    //Read in or create metadata file
		    ArrayList<Metadata> metadata = null;
		    //read in meatadata file
		    FileInputStream fileIn;
		    File metaFile = new File(METADATAFILE);
		    
		    if (metaFile.isFile() && metaFile.canRead()){ 		        
			    fileIn = new FileInputStream(METADATAFILE);
			    //decrypt it with private key
			    String used_key = privateKey.toString().substring(0, 16);
				String line;
				try (BufferedReader brr = new BufferedReader(new FileReader(METADATAFILE))) {
					line = brr.readLine();
				}
				String[] parts = line.split(" ");
				int[] ints = new int[parts.length];
				for (int i = 0; i < parts.length; i++) {
					ints[i] = Integer.parseInt(parts[i]);
				}
				byte[] bb = new byte[ints.length];
				for (int i = 0; i < ints.length; i++) {
					bb[i] = ByteBuffer.allocate(4).putInt(ints[i]).array()[3];
				}
				String decryptedMetaDataFile = AESFile.decrypt(bb, used_key);
				String[] lines = decryptedMetaDataFile.split("\n");
				
				//construct as arraylist
				metadata = new ArrayList<Metadata>();
				//System.out.println(lines[0]);

				for(int i = 0; i<lines.length; i++ ){
					String[] data = lines[i].split(":");
					Metadata md;

					if(Integer.parseInt(data[3])  == 0)  {
						md = new Metadata(DatatypeConverter.parseHexBinary(data[0]), data[1], data[2], Integer.parseInt(data[3]), null);
					}else{						
						md = new Metadata(DatatypeConverter.parseHexBinary(data[0]), data[1], data[2], Integer.parseInt(data[3]), DatatypeConverter.parseHexBinary(data[4].trim()));
					}
					metadata.add(md);
				}
				fileIn.close();
		    } else {
		    	metadata = new ArrayList<Metadata>();
		    }
		    
		    //Read in or create delegation file 
		    ArrayList<Delegation> delegations = null;
		    FileInputStream fileIn2;
		    File delegationFile = new File(DELEGATIONFILE);
		    if (delegationFile.isFile() && delegationFile.canRead()){
		    	fileIn2 = new FileInputStream(DELEGATIONFILE);
			    //decrypt it with private key
			    String used_key = privateKey.toString().substring(0, 16);
				String line;
				try (BufferedReader brr = new BufferedReader(new FileReader(DELEGATIONFILE))) {
					line = brr.readLine();
				}
				String[] parts = line.split(" ");
				int[] ints = new int[parts.length];
				for (int i = 0; i < parts.length; i++) {
					ints[i] = Integer.parseInt(parts[i]);
				}
				byte[] bb = new byte[ints.length];
				for (int i = 0; i < ints.length; i++) {
					bb[i] = ByteBuffer.allocate(4).putInt(ints[i]).array()[3];
				}
				String decryptedDelegationFile = AESFile.decrypt(bb, used_key);
				String[] lines = decryptedDelegationFile.split("\n");
				//construct as arraylist
				if(lines[0].trim().length()==0){
			    	delegations = new ArrayList<Delegation>();
				}else{
					delegations = new ArrayList<Delegation>();
					for(int i = 0; i<lines.length; i++ ){
						String[] data = lines[i].split(":");
						//byte[] id, String c, int d, boolean p, int r		
						//System.out.println("!!!:"+DatatypeConverter.parseHexBinary(data[0])+"  "+data[1]+" "+ Integer.parseInt(data[2]) +" " + Boolean.valueOf(data[3]) + " "+Integer.parseInt(data[4].trim()));
						Delegation d = new Delegation(DatatypeConverter.parseHexBinary(data[0]), data[1], 0,  Boolean.valueOf(data[3]), Integer.parseInt(data[4].trim()));
						delegations.add(d);
					}
				}
				fileIn2.close();
		    	
		        
		    } else {
		    	delegations = new ArrayList<Delegation>();
		    }
		    

		    //Start listening for connections
		    ServerSocket serverSocket = new ServerSocket(6789);
		    
		    //Loop until stopped
	   		System.out.println("Waiting For Connections...");
	   		while(!quit){
	   			//Accept client connection
	   			Socket socket = serverSocket.accept();
	   			DataInputStream socketIn = new DataInputStream(socket.getInputStream());
	   			DataOutputStream socketOut = new DataOutputStream(socket.getOutputStream());
	   			
   				//Looks up username in keystore
	   			cipherText = new byte[socketIn.readInt()];
		   		socketIn.readFully(cipherText);
		   		String username = new String(AsymDecrypt(cipherText, privateKey)).toLowerCase();
			    System.out.println(socket.getRemoteSocketAddress() + ": Received Username - " + username);
   				
   				//load client key based on username
   				Certificate clientCert = keystore.getCertificate(username);
   				
   				if(clientCert != null){
   					Key clientKey = clientCert.getPublicKey();
   					
   					cipherText = "Success".getBytes();
				    socketOut.writeInt(cipherText.length);
				    socketOut.write(cipherText);
				    
	   				//Read in session key from client
		   			cipherText = new byte[socketIn.readInt()];
			   		socketIn.readFully(cipherText);
			   		SecretKey sessionKey = new SecretKeySpec(AsymDecrypt(cipherText, privateKey), "AES");
				    System.out.println(socket.getRemoteSocketAddress() + ": Received - " + bytesToHex(sessionKey.getEncoded()));
		   			
				    //Verify data based on loaded client key 
				    byte[] sig = new byte[socketIn.readInt()];
			   		socketIn.readFully(sig);
			   		boolean valid = verifySig(cipherText, sig, (PublicKey)clientKey);
			   		System.out.println(socket.getRemoteSocketAddress() + ": Received - " + bytesToHex(sig));
				    
			   		if(valid){
					    //Send IV
			   			byte[] iv = new byte[AES_KEY_SIZE / 8];
			   			random.nextBytes(iv);
			   			cipherText = AsymEncrypt(iv, clientKey);
					    socketOut.writeInt(cipherText.length);
					    socketOut.write(cipherText);
					    System.out.println(socket.getRemoteSocketAddress() + ": Sent - " + bytesToHex(iv));
					    
					    //Sign IV and send signature
					    sig = createSig(cipherText, (PrivateKey)privateKey);
					    socketOut.writeInt(sig.length);
					    socketOut.write(sig);
					    System.out.println(socket.getRemoteSocketAddress() + ": Sent - " + bytesToHex(sig));
					    
					    //Initialize symmetric key objects
					    encCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
					    decCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(iv));
					    
					    //Encrypt success status and send
					    cipherText = SymmetricCrypt("Success".getBytes(), encCipher);
					    socketOut.writeInt(cipherText.length);
					    socketOut.write(cipherText);
					    
				    	connected = true;
				    	System.out.println(socket.getRemoteSocketAddress() + ": Connection Established");
				    }
	   			} else {
	   				cipherText = "Failure".getBytes();
				    socketOut.writeInt(cipherText.length);
				    socketOut.write(cipherText);
				    
				    System.out.println(socket.getRemoteSocketAddress() + ": Invalid Username");
	   			}
	   		
	   			String input;
   				while(connected){
   					cipherText = new byte[socketIn.readInt()];
			   		socketIn.readFully(cipherText);
			   		input = new String(SymmetricCrypt(cipherText, decCipher));
			   		System.out.println(socket.getRemoteSocketAddress() + ": Received - " + input);
			   		
			   		String[] command = input.split("\\(|\\)|,");
					switch (command[0]) {
					case "get":
						boolean success = false;
						
						//search for file based on uid or filename
						fileMetadata = null;
						for(Metadata f : metadata){
							if(bytesToHex(f.uid).equals(command[1])){
								fileMetadata = f;
								break;
							}
							if(f.filename.equals(command[1]) && (f.owner == username || fileMetadata == null)){
								fileMetadata = f;
						    }
						}
						
						if(fileMetadata != null){
							uid = fileMetadata.uid;
							
							//Grant access if user owns requested file
							hasAccess = false;
							if(username.equals(fileMetadata.owner)){
								hasAccess = true;
							} else {
								//Grant access if there is a valid delegation token
								for(Delegation d : delegations){
									if(fileMetadata.equals(d.uid)
										&& (d.client.equals("all") || d.client.equals(username)) 
										&& !d.isExpired()
										&& d.rights != 2){
										hasAccess = true;
										break;
								    }
								}
							}
							
							//If everything is valid, send file
							if(hasAccess){
								//Load file
								Path p = FileSystems.getDefault().getPath("", bytesToHex(uid));//
						        fileBytes = Files.readAllBytes(p);
								
								//If integrity, check file hash
						        boolean verified = true;
								if(fileMetadata.securityLevel == 2){
									byte[] hash = getHash(fileBytes);
									verified = verifySig(hash, fileMetadata.secureParam, (PublicKey)publicKey);//
								}
								
								if(verified){
									cipherText = SymmetricCrypt("Success".getBytes(), encCipher);
								    socketOut.writeInt(cipherText.length);
								    socketOut.write(cipherText);	
								} else {
									cipherText = SymmetricCrypt("Invalid".getBytes(), encCipher);
								    socketOut.writeInt(cipherText.length);
								    socketOut.write(cipherText);
								    
								    System.out.println(socket.getRemoteSocketAddress() + ": ERROR File Modified - " + bytesToHex(uid));
								}
						        
								if(fileMetadata.securityLevel == 1){
									//get aes key from metadata
									Key aesKey = null;
									byte[] fileKey = fileMetadata.secureParam; 									
							   		SecretKey sessionKey2 = new SecretKeySpec(AsymDecrypt(fileKey, privateKey), "AES");
							   		aesKey = sessionKey2;
							   		
						   			byte[] iv2 = { 4, 0, 0, 0, 1, 7, 17, 20, 4, 0, 0, 0, 1, 7, 17, 20};
								    decCipher2.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv2));
									fileBytes = SymmetricCrypt(fileBytes, decCipher2);
								}
								//send file
						        cipherText = SymmetricCrypt(fileBytes, encCipher);
							    socketOut.writeInt(cipherText.length);
							    socketOut.write(cipherText);
							    
							    //send slevel
							    String slevelString = Integer.toString(fileMetadata.securityLevel);
							    byte[] slevelByte = slevelString.getBytes();
						        cipherText = SymmetricCrypt(slevelByte, encCipher);
							    socketOut.writeInt(cipherText.length);
							    socketOut.write(cipherText);
							    
							    
							    System.out.println(socket.getRemoteSocketAddress() + ": Sent File - " + bytesToHex(uid));
							    success = true;
							} else {
								System.out.println(socket.getRemoteSocketAddress() + ": ERROR Denied Access - " + bytesToHex(uid));
							}
						} else {
							System.out.println(socket.getRemoteSocketAddress() + ": ERROR Unable to Locate File");
						}
						
						//Send error message if error occurred while retrieving file
						if (!success) {
							cipherText = SymmetricCrypt("Failed".getBytes(), encCipher);
						    socketOut.writeInt(cipherText.length);
						    socketOut.write(cipherText);
						}
						break;
					case "put":
						//Look for existing files not owned by user
						fileMetadata = null;
						for(Metadata f : metadata){
							if((bytesToHex(f.uid).equals(command[1]) && f.owner != username) 
									|| (f.filename.equals(command[1]) && f.owner == username)){
						    	fileMetadata = f;
						    }
						}
						
						//Ensure user has rights to put file
						hasAccess = false;
						uid = null;
						if(fileMetadata == null){
							hasAccess = true;
							String str = username + command[1];
							uid = getHash(str.getBytes());
						} else if(fileMetadata.owner == username){
							hasAccess = true;
							uid = fileMetadata.uid;
						} else {
							for(Delegation d : delegations){
								if(fileMetadata.equals(d.uid) 
										&& (d.client.equalsIgnoreCase("ALL") || d.client.equalsIgnoreCase(username)) 
										&& !d.isExpired()
										&& d.rights != 1){
									hasAccess = true;
									uid = d.uid;
							    }
							}
						}
						
						if(hasAccess){
							cipherText = SymmetricCrypt("Success".getBytes(), encCipher);
						    socketOut.writeInt(cipherText.length);
						    socketOut.write(cipherText);
							
							//Receive file
							cipherText = new byte[socketIn.readInt()];
					   		socketIn.readFully(cipherText);
					   		fileBytes = SymmetricCrypt(cipherText, decCipher);
							
					   		//Determine security flag assigned to file
							int securityLevel = 0;
							if(command[2].toUpperCase().trim().equalsIgnoreCase(SECURITY_FLAGS[1]))
								securityLevel = 1;
							else if(command[2].toUpperCase().trim().equalsIgnoreCase(SECURITY_FLAGS[2]))
								securityLevel = 2;
					   		
					   		//Encrypt file if 'confidential'
							Key aesKey = null;
							byte[] fileKey = null;
							if(securityLevel == 1){
								KeyGenerator kgen = KeyGenerator.getInstance("AES");
								aesKey = kgen.generateKey();
								byte[] iv2 = { 4, 0, 0, 0, 1, 7, 17, 20, 4, 0, 0, 0, 1, 7, 17, 20};
							    encCipher2.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv2));
								fileBytes = SymmetricCrypt(fileBytes, encCipher2);
								
								fileKey = AsymEncrypt(aesKey.getEncoded(), publicKey);
							} else if (securityLevel == 2){
								//create signature if 'integrity'
								byte[] hash = getHash(fileBytes);
								fileKey = createSig(hash, (PrivateKey)privateKey); //*
							}
							
							//Add object if new file, else change security information
							if(fileMetadata == null){
								fileMetadata = new Metadata(uid, command[1], username, securityLevel, fileKey);
								metadata.add(fileMetadata);
							} else {
								fileMetadata.setSecurity(securityLevel,  fileKey);
							}
							
							//Write out file
							FileOutputStream out = new FileOutputStream(bytesToHex(uid));
							out.write(fileBytes);
							out.close();
							
							//Send confirmation
							if(fileMetadata.owner.equals(username)){
								cipherText = SymmetricCrypt("Success".getBytes(), encCipher);
							    socketOut.writeInt(cipherText.length);
							    socketOut.write(cipherText);
							} else {
								cipherText = SymmetricCrypt("Updated".getBytes(), encCipher);
							    socketOut.writeInt(cipherText.length);
							    socketOut.write(cipherText);
							}
							
						    //add metatdata print
						    System.out.println(socket.getRemoteSocketAddress() + ": Stored - " + fileMetadata.toString());
						    System.out.println("Metadata:");
						    for(Metadata m : metadata)
						    	System.out.println(m.toString());
						} else {
							cipherText = SymmetricCrypt("Failure".getBytes(), encCipher);
						    socketOut.writeInt(cipherText.length);
						    socketOut.write(cipherText);
						    
						    System.out.println(socket.getRemoteSocketAddress() + ": ERROR Denied Access - " + fileMetadata.toString());
						}
						
						break;
					case "delegate":
						//find file based on UID or filename
						fileMetadata = null;
						for(Metadata f : metadata){
							if(bytesToHex(f.uid).equals(command[1])){
								fileMetadata = f;
						    	break;
						    }
							if(f.filename.equals(command[1]) && (username.equals(f.owner) || fileMetadata == null)){
							    fileMetadata = f;
							}
						}
						
						//if file found, create delegation object
						if(fileMetadata != null){
							
							//determine access right delegated
							int access = 0;
							if(command[5].trim().equalsIgnoreCase(ACCESS_RIGHTS[1]))
								access = 1;
							else if(command[5].trim().equalsIgnoreCase(ACCESS_RIGHTS[2]))
								access = 2;
							
							hasAccess = false;
							if(fileMetadata.owner.equals(username)){
								hasAccess = true;
							} else {
								for(Delegation d : delegations){
									if(fileMetadata.equals(d.uid) 
											&& (d.client.equalsIgnoreCase("ALL") || d.client.equalsIgnoreCase(username)) 
											&& !d.isExpired()
											&& d.propagation
											&& (d.rights == 0 || d.rights == access)){
										hasAccess = true;
								    }
								}
							}
							
							if(hasAccess){
								uid = fileMetadata.uid;
								
								//parse command for values
								String client = command[2].toLowerCase().trim();
								int duration = Integer.parseInt(command[3].trim());
								boolean propogate = Boolean.parseBoolean(command[4].toLowerCase().trim());
								
								//generate delegation token and add to list
								Delegation delegation = new Delegation(uid, client, duration, propogate, access);
								delegations.add(delegation);
								
								//Send confirmation
								cipherText = SymmetricCrypt("Success".getBytes(), encCipher);
							    socketOut.writeInt(cipherText.length);
							    socketOut.write(cipherText);
							    
							    System.out.println("Delegations:");
							    for(Delegation d : delegations)
							    	System.out.println(d.toString());
							} else {
								cipherText = SymmetricCrypt("Denied".getBytes(), encCipher);
							    socketOut.writeInt(cipherText.length);
							    socketOut.write(cipherText);	
							}
						} else {
							//File doesn't exist
							cipherText = SymmetricCrypt("Failure".getBytes(), encCipher);
						    socketOut.writeInt(cipherText.length);
						    socketOut.write(cipherText);
						}
						
						break;
					case "end-session":
						//receive number of file need to update
	   					cipherText = new byte[socketIn.readInt()];
				   		socketIn.readFully(cipherText);
				   		String number_to_update_string = new String(SymmetricCrypt(cipherText, decCipher));
						int number_to_update = Integer.parseInt(number_to_update_string);
				   		
						//receive updates
						for(int i = 0; i < number_to_update; i++){
							//Receive file
							cipherText = new byte[socketIn.readInt()];
					   		socketIn.readFully(cipherText);
					   		fileBytes = SymmetricCrypt(cipherText, decCipher);
					   		
							//Receive file name
							cipherText = new byte[socketIn.readInt()];
					   		socketIn.readFully(cipherText);
					   		byte[] fileNameByte = SymmetricCrypt(cipherText, decCipher);
					   		String fileName = new String(fileNameByte, "UTF-8");
					   		
					   		//receive security flag
							cipherText = new byte[socketIn.readInt()];
					   		socketIn.readFully(cipherText);
					   		byte[] sFlagBytes = SymmetricCrypt(cipherText, decCipher);
					   		String sFlagString = new String(sFlagBytes, "UTF-8");
					   		int securityLevel = Integer.parseInt(sFlagString);
					   		
					   		//Encrypt file if 'confidential'
							Key aesKey = null;
							byte[] fileKey = null;
							if(securityLevel == 1){
								KeyGenerator kgen = KeyGenerator.getInstance("AES");
								aesKey = kgen.generateKey();
								byte[] iv2 = { 4, 0, 0, 0, 1, 7, 17, 20, 4, 0, 0, 0, 1, 7, 17, 20};
							    encCipher2.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv2));
								fileBytes = SymmetricCrypt(fileBytes, encCipher2);
								
								fileKey = AsymEncrypt(aesKey.getEncoded(), publicKey);
							} else if (securityLevel == 2){
								//create signature if 'integrity'
								byte[] hash = getHash(fileBytes);
								fileKey = createSig(hash, (PrivateKey)privateKey); //*
							}
					   		
							//Add object if new file, else change security information
							fileMetadata = null;
							for(Metadata f : metadata){
								if((bytesToHex(f.uid).equals(fileName) && f.owner != username) 
										|| (f.filename.equals(fileName) && f.owner == username)){
							    	fileMetadata = f;
							    }
							}
							if(fileMetadata != null){
								fileMetadata.setSecurity(securityLevel,  fileKey);
								
								//Write out file
								FileOutputStream out = new FileOutputStream(bytesToHex(fileMetadata.uid));
								out.write(fileBytes);
								out.close();
								
								System.out.println(fileName + " updated");
							}
						}

						
						connected = false;
						break;
					case "shutdown":
						//encrypt and store meta data file
						PrintWriter file = new PrintWriter(METADATAFILE, "UTF-8");
						String content = "";
						
						for (Metadata md : metadata){
							if(content != ""){
								content = content+"\n"+md.toString();						
							}else{
								content = md.toString();
							}
						}
						
						// padding to 8000 bytes (optional)
						int temp;
						if(content == ""){
							temp = 8000;
						}else{
							temp = (8000 - content.length());
						}
						for (int i = 0; i < temp; i++) {
							content = content + "\0";
						}
						System.out.println("\nMetadata file content:\n"+ content +"\n\n");
						String used_key = privateKey.toString().substring(0, 16);
						byte[] cipher = AESFile.encrypt(content, used_key); //only first 16 are used to enc/dec meta data file 
						for (int i = 0; i < cipher.length; i++) {
							file.print((cipher[i]) + " ");
						}
						file.close();
						
						
						//delegation store
						//It is designed that, if the server is shutdown, delegation record time will be all set to 0 
						PrintWriter dfile = new PrintWriter(DELEGATIONFILE, "UTF-8");
						String dcontent = "";
						for (Delegation d : delegations){
							if(dcontent != ""){
								dcontent = dcontent+"\n"+d.toString();						
							}else{
								dcontent = d.toString();
							}
						}
						
						// padding to 8000 bytes (optional)
						int dtemp;
						if(dcontent == "") {
							dtemp = 8000;
						}else{
							dtemp = (8000 - dcontent.length());
						}
						for (int i = 0; i < dtemp; i++) {
							dcontent = dcontent + "\0";
						}
						System.out.println("\nDelegation file content:\n"+ dcontent +"\n\n");
						byte[] dcipher = AESFile.encrypt(dcontent, used_key); //only first 16 are used to enc/dec meta data file 
						for (int i = 0; i < dcipher.length; i++) {
							dfile.print((dcipher[i]) + " ");
						}
						dfile.close();
						
						connected = false;
						quit = true;
						break;
					default:
						break;
					}
   				}
	   			socketIn.close();
				socketOut.close();
				socket.close();
			}
	        serverSocket.close();
	        
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e1) {
			System.out.println("System does not contain required encryption algorithms");
		}
	}
}