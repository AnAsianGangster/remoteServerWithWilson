import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class EncryptandDecrypt {
    // paths
	private static final String publicKeyPath = "./cert/public_key.der";
	private static final String privateKeyPath = "./cert/private_key.der";
    /**
	 * encryption
	 * 
	 * @param inputData
	 * @param keyType
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryption(String inputData, String keyType) throws Exception {
		final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		if (keyType == "public") {
			PublicKey key = PublicKeyReader.get(publicKeyPath);

			// cipher init
			cipher.init(Cipher.ENCRYPT_MODE, key);

			byte[] byteInputData = inputData.getBytes();

			byte[] encryptedBytesArray = cipher.doFinal(byteInputData);

			return encryptedBytesArray;
		} else if (keyType == "private") {
			PrivateKey key = PrivateKeyReader.get(privateKeyPath);

			// cipher init
			cipher.init(Cipher.ENCRYPT_MODE, key);

			byte[] byteInputData = inputData.getBytes();

			byte[] encryptedBytesArray = cipher.doFinal(byteInputData);

			return encryptedBytesArray;
		} else {
			System.out.println("Invalid key type");
			return null;
		}
	}

	public static byte[] encryptionByte(byte[] inputData, String keyType) throws Exception {
		final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		if (keyType == "public") {
			PublicKey key = PublicKeyReader.get(publicKeyPath);

			// cipher init
			cipher.init(Cipher.ENCRYPT_MODE, key);

			byte[] encryptedBytesArray = cipher.doFinal(inputData);

			return encryptedBytesArray;
		} else if (keyType == "private") {
			PrivateKey key = PrivateKeyReader.get(privateKeyPath);

			// cipher init
			cipher.init(Cipher.ENCRYPT_MODE, key);

			byte[] encryptedBytesArray = cipher.doFinal(inputData);

			return encryptedBytesArray;
		} else {
			System.out.println("Invalid key type");
			return null;
		}
	}


	/**
	 * decryption
	 * @param inputDataToDecrypt
	 * @param keyType
	 * @return
	 * @throws Exception
	 */
	public static String decryption(byte[] inputDataToDecrypt, String keyType) throws Exception {

		final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		if(keyType == "public"){
			PublicKey key = PublicKeyReader.get(publicKeyPath);

			cipher.init(Cipher.DECRYPT_MODE, key);

			byte[] decryptedBtyesArray = cipher.doFinal(inputDataToDecrypt);

			return new String(decryptedBtyesArray);
		} else if(keyType == "private"){
			PrivateKey key = PrivateKeyReader.get(privateKeyPath);

			cipher.init(Cipher.DECRYPT_MODE, key);

			byte[] decryptedBtyesArray = cipher.doFinal(inputDataToDecrypt);

			return new String(decryptedBtyesArray);
		} else {
			System.out.println("Invalid key type");
			return null;
		}
	}

		/**
	 * decryption
	 * @param inputDataToDecrypt
	 * @param keyType
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptionByte(byte[] inputDataToDecrypt, String keyType) throws Exception {

		final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		if(keyType == "public"){
			PublicKey key = PublicKeyReader.get(publicKeyPath);

			cipher.init(Cipher.DECRYPT_MODE, key);

			byte[] decryptedBtyesArray = cipher.doFinal(inputDataToDecrypt);

			return decryptedBtyesArray;
		} else if(keyType == "private"){
			PrivateKey key = PrivateKeyReader.get(privateKeyPath);

			cipher.init(Cipher.DECRYPT_MODE, key);

			byte[] decryptedBtyesArray = cipher.doFinal(inputDataToDecrypt);

			return decryptedBtyesArray;
		} else {
			System.out.println("Invalid key type");
			return null;
		}
	}


}