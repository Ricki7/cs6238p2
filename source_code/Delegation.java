import java.io.Serializable;
import java.util.Date;

public class Delegation implements Serializable{
	private static final long serialVersionUID = -8859648877283655093L;
	byte[] uid;
	String client;
	Date expireDate;
	boolean propagation;
	int rights;
	
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
	
	public Delegation(byte[] id, String c, int d, boolean p, int r){
		uid = id;
		client = c;
		
		Date date = new Date();
		expireDate = new Date(date.getTime() + (d * 1000));
		
		propagation = p;
		rights = r;
	}
	
	public boolean isExpired(){
		Date date = new Date();
		return date.after(expireDate);
	}
	
	@Override
	public String toString(){
		return bytesToHex(this.uid) + ":" + this.client + ":" + this.expireDate.getTime() + ":" + this.propagation + ":" + this.rights;
	}
}
