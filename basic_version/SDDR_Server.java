
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;

//both - try catch statements

public class SDDR_Server {
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
        byte[] uid;
        Metadata fileMetadata;
        byte[] fileBytes;
        byte[] cipherText;
        FileOutputStream out;
        
		try {
		    //create metadata and delegations objects
		    ArrayList<Metadata> metadata = new ArrayList<Metadata>();

		    //Start listening for connections
		    ServerSocket serverSocket = new ServerSocket(6789);
		    
		    //Loop until stopped
	   		System.out.println("Waiting For Connections...");
	   		while(!quit){
	   			//Accept client connection
	   			Socket socket = serverSocket.accept();
	   			DataInputStream socketIn = new DataInputStream(socket.getInputStream());
	   			DataOutputStream socketOut = new DataOutputStream(socket.getOutputStream());
	   			
	   			//get username
	   			cipherText = new byte[socketIn.readInt()];
		   		socketIn.readFully(cipherText);
		   		String username = new String(cipherText).toLowerCase();
			    System.out.println(socket.getRemoteSocketAddress() + ": Received Username - " + username);
   				
				cipherText = "Success".getBytes();
			    socketOut.writeInt(cipherText.length);
			    socketOut.write(cipherText);
			    
			    System.out.println("here");
			    
	   			String input;
	   			connected = true;
   				while(connected){
   					cipherText = new byte[socketIn.readInt()];
			   		socketIn.readFully(cipherText);
			   		input = new String(cipherText);
			   		System.out.println(socket.getRemoteSocketAddress() + ": Received - " + input);
			   		
			   		System.out.println(input);
			   		
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
							
							//Load file
							Path p = FileSystems.getDefault().getPath("", bytesToHex(uid));//
					        fileBytes = Files.readAllBytes(p);
							
							cipherText = "Success".getBytes();
						    socketOut.writeInt(cipherText.length);
						    socketOut.write(cipherText);	
					        
							//send file
						    socketOut.writeInt(fileBytes.length);
						    socketOut.write(fileBytes);
							    
						    System.out.println(socket.getRemoteSocketAddress() + ": Sent File - " + bytesToHex(uid));
						    success = true;
						} else {
							System.out.println(socket.getRemoteSocketAddress() + ": ERROR Unable to Locate File");
						}
						
						//Send error message if error occurred while retrieving file
						if (!success) {
							cipherText = "Failed".getBytes();
						    socketOut.writeInt(cipherText.length);
						    socketOut.write(cipherText);
						}
						break;
					case "put":
						//Look for existing files not owned by user
						fileMetadata = null;
						for(Metadata f : metadata){
							if((bytesToHex(f.uid).equals(command[1]) || f.filename.equals(command[1]))){
						    	fileMetadata = f;
						    }
						}
							
						//Receive file
						fileBytes = new byte[socketIn.readInt()];
				   		socketIn.readFully(fileBytes);
							
						//Add object if new file
				   		String str = username + command[1];
						uid = getHash(str.getBytes());
						if(fileMetadata == null){
							fileMetadata = new Metadata(uid, command[1], username, 0, null);
							metadata.add(fileMetadata);
						}
							
						//Write out file
						out = new FileOutputStream(bytesToHex(uid));
						out.write(fileBytes);
						out.close();
							
						//Send confirmation
						if(fileMetadata.owner.equals(username)){
							cipherText = "Success".getBytes();
						    socketOut.writeInt(cipherText.length);
						    socketOut.write(cipherText);
						} else {
							cipherText = "Updated".getBytes();
						    socketOut.writeInt(cipherText.length);
						    socketOut.write(cipherText);
						}
						
					    //add metatdata print
					    System.out.println(socket.getRemoteSocketAddress() + ": Stored - " + fileMetadata.toString());
					    System.out.println("Metadata:");
					    for(Metadata m : metadata)
					    	System.out.println(m.toString());
						
						break;
					case "end-session":
						//receive number of file need to update
	   					cipherText = new byte[socketIn.readInt()];
				   		socketIn.readFully(cipherText);
				   		String number_to_update_string = new String(cipherText);
						int number_to_update = Integer.parseInt(number_to_update_string);
				   		
						//receive updates
						for(int i = 0; i < number_to_update; i++){
							//Receive file
							cipherText = new byte[socketIn.readInt()];
					   		socketIn.readFully(cipherText);
					   		fileBytes = cipherText;
					   		
							//Receive file name
							cipherText = new byte[socketIn.readInt()];
					   		socketIn.readFully(cipherText);
					   		byte[] fileNameByte = cipherText;
					   		String fileName = new String(fileNameByte, "UTF-8");
					   							   		
							//Add object if new file, else change security information
							fileMetadata = null;
							for(Metadata f : metadata){
								if(bytesToHex(f.uid).equals(fileName) && f.owner != username 
										|| f.filename.equals(fileName) && f.owner == username){
							    	fileMetadata = f;
							    }
							}
							if(fileMetadata != null){
								//Write out file
								out = new FileOutputStream(bytesToHex(fileMetadata.uid));
								out.write(fileBytes);
								out.close();
										
								System.out.println(fileName + " updated");
							}
						}
						
						connected = false;
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
		} catch (Exception e1) {
		}
	}
}