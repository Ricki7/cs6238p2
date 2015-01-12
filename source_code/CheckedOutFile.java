
public class CheckedOutFile {
	String fileName;
	byte[] hash = null;
	int securityLevel = 0;
	
	public CheckedOutFile(String fileName, byte[] hash, int s){
		this.fileName = fileName;
		this.hash = hash;
		this.securityLevel= s;
	}

	public String toString(){
		return fileName+":"+bytesToHex(this.hash);
	}
	
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
}
