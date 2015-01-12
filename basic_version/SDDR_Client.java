import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

public class SDDR_Client {
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
		
	public static void main(String[] args) throws Exception{
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
   		
   		Date date = new Date();
	    System.out.println(date.getTime());
   		
		//Select user
		System.out.printf("Username:");
		String username = inFromUser.readLine();
		
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
				    
				    //Send username
					cipherText = username.getBytes();
					socketOut.writeInt(cipherText.length);
				    socketOut.write(cipherText);
				    
				    //Receive status message 
				    cipherText = new byte[socketIn.readInt()];
			   		socketIn.readFully(cipherText);
			   		plainText = new String(cipherText);
			   		
			   		if(plainText.equals("Success"));
			   			System.out.println("Connection Established");
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
					
					//send get command
					cipherText = input.getBytes();
				    socketOut.writeInt(cipherText.length);
				    socketOut.write(cipherText);
					System.out.println("Sent: " + input);
					
					//receive status command
					cipherText = new byte[socketIn.readInt()];
			   		socketIn.readFully(cipherText);
			   		plainText = new String(cipherText);

			   		if(plainText.equals("Success")){
				   		cipherText = new byte[socketIn.readInt()];
				   		socketIn.readFully(cipherText);
				   		byte[] fileBytes = cipherText;
				   		
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
							CheckedOutFile cof = new CheckedOutFile(command[1], hash, 0);
							checkedOutFiles.add(cof);
						}

						System.out.println("File downloaded successfully");
			   		} else {
			   			System.out.println("File download failed");
			   		}
					break;
				case "put":
					//Ensure proper usage and user is connected
					if(command.length != 2){
						System.out.println("Invalid Number of Arguments");
						break;
					}
					if(socket == null){
						System.out.println("No session established");
						break;
					}
				    
					//send command
					cipherText = input.getBytes();
				    socketOut.writeInt(cipherText.length);
				    socketOut.write(cipherText);
					System.out.println("Sent: " + input);
					
				    //read-in file
					plainText = "";
				    try{
				    	Path p = FileSystems.getDefault().getPath(username, command[1]);
				        byte [] fileData = Files.readAllBytes(p);
				   		
						//send file
					    socketOut.writeInt(fileData.length);
					    socketOut.write(fileData);
					    
						//receive status command
					    cipherText = new byte[socketIn.readInt()];
				   		socketIn.readFully(cipherText);
				   		plainText = new String(cipherText);
				   		if(verbose)
				   			System.out.println(socket.getRemoteSocketAddress() + ": " + plainText);
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
						cipherText = "end-session".getBytes();
					    socketOut.writeInt(cipherText.length);
					    socketOut.write(cipherText);
						System.out.println("Sent: " + input);
						
						//send number of files that need to update
						cipherText = Integer.toString(number_to_update).getBytes();
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
							    socketOut.writeInt(fileData.length);
							    socketOut.write(fileData);
							    
								//send file name
						        cipherText = cof.fileName.getBytes();
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
				default:
					System.out.println("Unknown command");
					break;
				}
			}
		}
	}
}
