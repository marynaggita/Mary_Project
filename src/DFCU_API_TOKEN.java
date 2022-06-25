import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

public class DFCU_API_TOKEN {

	private Cipher cipher;
	
	public static void main(String[] args) throws Exception {
		String username="mary";
		String password="password1$";
		
		String username_password = username+password;
		
		
		Charset utf8charset = Charset.forName("UTF-8");
		Charset iso88591charset = Charset.forName("ISO-8859-1");

		ByteBuffer inputBuffer = ByteBuffer.wrap(username_password.getBytes());

		// decode UTF-8
		CharBuffer data = utf8charset.decode(inputBuffer);

		// encode ISO-8559-1
		ByteBuffer outputBuffer = iso88591charset.encode(data);
		byte[] outputData = outputBuffer.array();
		
		
		//System.out.println("Output data: "+outputData.toString());
		
		System.out.println("Output data: "+new String(outputData, StandardCharsets.UTF_8));
		
		String base64String = java.util.Base64.getEncoder().encodeToString(outputData);
		
		
		System.out.println("Base 64: "+base64String);
		
		String string_w_basic = "Basic"+" "+base64String;
		
		System.out.println("String with basic: "+string_w_basic);
		
		String Authheader = Encrypt(string_w_basic);
		
		System.out.println("Authheader: "+Authheader);

	}
	
	public static String Encrypt(String string_w_basic) throws Exception {
		
		DFCU_API_TOKEN ac = new DFCU_API_TOKEN();
		PublicKey publicKey = ac.getPublic("src/resources/keystore/public.der");
		
		String encrypted_token= null;
		if(publicKey !=null) {
			 encrypted_token = ac.encryptText(string_w_basic, publicKey);
			
			/*System.out.println("Original Message: " + string_w_basic + 
				"\nEncrypted Message: " + encrypted_token);*/
		}else {
			System.out.println("publicKey not found");
		}
		

		
		return encrypted_token;
		
		
	}
	
	public String encryptText(String msg, PublicKey key) 
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			UnsupportedEncodingException, IllegalBlockSizeException, 
			BadPaddingException, InvalidKeyException {
		this.cipher = Cipher.getInstance("RSA");
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
	}
	
	// https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
		public PrivateKey getPrivate(String filename) throws Exception {
			byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		}

		// https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
		public PublicKey getPublic(String filename) throws Exception {
			byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
		}
		
		
		 
		 
		 
		 

}
