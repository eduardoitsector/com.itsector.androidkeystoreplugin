import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

import android.content.Context;

import android.util.Base64;
import android.util.Log;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import java.math.BigInteger;

import android.security.KeyPairGeneratorSpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;

public class AndroidKeystorePlugin extends CordovaPlugin {

	static final String CIPHER_TYPE = "RSA/ECB/PKCS1Padding";
    static final String CIPHER_PROVIDER = "AndroidOpenSSL";
	KeyStore keyStore;
	
	@Override
	public void initialize(CordovaInterface cordova, CordovaWebView webView) {
		super.initialize(cordova, webView);
		
		try{
			
			keyStore = KeyStore.getInstance("AndroidKeyStore");
			keyStore.load(null);
			
		} catch (Exception e) {
        }
	}

    @Override
    public boolean execute(String action, JSONArray data, CallbackContext callbackContext) throws JSONException {
		if (action.equals("decrypt")) {

            String toDecrypt = data.getString(0);
			String alias = data.getString(1);
			String decrypted = decryptString(toDecrypt, alias);
            callbackContext.success(decrypted);

            return true;

        } else if (action.equals("encrypt")) {

            String toEncrypt = data.getString(0);
			String alias = data.getString(1);
            String encrypted = encryptString(toEncrypt, alias);
            callbackContext.success(encrypted);

            return true;

        } else {
            
            return false;

        }
    }
	
	public String decryptString(String toDecrypt, String alias) {
        try {
			
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
            RSAPrivateKey privateKey = (RSAPrivateKey) privateKeyEntry.getPrivateKey();

            Cipher output = Cipher.getInstance(CIPHER_TYPE, CIPHER_PROVIDER);
            output.init(Cipher.DECRYPT_MODE, privateKey);

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(toDecrypt, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            return new String(bytes, 0, bytes.length, "UTF-8");
			
        } catch (Exception e) {
			
			return "ERROR " + e.getMessage();
			
        }
    }
	
	public String encryptString(String toEncrypt, String alias) {
        try {
			
			RSAPublicKey publicKey;
			
			// Create new key if needed
			if (!keyStore.containsAlias(alias)) {
				
				Calendar start = Calendar.getInstance();
				Calendar end = Calendar.getInstance();
				//end.add(Calendar.MINUTE, 10);
				end.add(Calendar.YEAR, 1);
				KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(cordova.getActivity().getApplicationContext())
						.setAlias(alias)
						.setSubject(new X500Principal("CN=AndroidKeystorePlugin, O=ITSector"))
						.setSerialNumber(BigInteger.ONE)
						.setStartDate(start.getTime())
						.setEndDate(end.getTime())
						.build();
				KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
				generator.initialize(spec);

				KeyPair keyPair = generator.generateKeyPair();
				publicKey = (RSAPublicKey) keyPair.getPublic();
				
			} else {
				
				KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
				publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();
				
			}

            Cipher inCipher = Cipher.getInstance(CIPHER_TYPE, CIPHER_PROVIDER);
            inCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, inCipher);
            cipherOutputStream.write(toEncrypt.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte [] vals = outputStream.toByteArray();
			
			return Base64.encodeToString(vals, Base64.DEFAULT);
			
        } catch (Exception e) {
			
            return e.getMessage();
			
        }
    }

}
