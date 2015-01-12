import java.io.Serializable;
import java.util.Arrays;

class Metadata implements Serializable{
	private static final long serialVersionUID = -1474524415624487409L;
	byte[] uid = null;
	String filename = null;
	String owner = null;
	int securityLevel = 0;
	byte[] secureParam = null;
	
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
	
	public Metadata(byte[] id, String fname, String own, int slevel, byte[] p){
		this.uid = id;
		this.filename = fname;
		this.owner = own;
		this.securityLevel = slevel;
		this.secureParam = p;
	}
	
	@Override
	public String toString(){
		return bytesToHex(this.uid) + ":" + this.filename + ":" + this.owner + ":" + this.securityLevel + ":" + bytesToHex(this.secureParam);
	}
	
	public boolean equals(byte[] tmp_uid){
		return Arrays.equals(tmp_uid, this.uid);
	}
	
	public void setSecurity(int slevel, byte[] p){
		this.securityLevel = slevel;
		this.secureParam = p;
	}
}
