import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ProcessBuilder.Redirect;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.print.DocFlavor.STRING;

public class ServerCP2 {

	// paths
	private static final String publicKeyPath = "./certMac/public_key.der";
	private static final String privateKeyPath = "./certMac/private_key.der";

	// static messages
	private static final String serverHelloMessage = "Hello, this is server at: ";
	private static final String correctQueryMessage = "GET CA";

	public static void main(String[] args) throws Exception {

		int port = 4321;
		if (args.length > 0)
			port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		InputStream fis;
		CertificateFactory cf;
		X509Certificate CAcert;
		PublicKey key;

		SecretKey desKey = null;

		Path certPath = Paths.get("./cert/example-19f80660-82c3-11ea-ae9d-89114163ae84.crt");

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			fis = new FileInputStream("./cert/cacse.crt");
			cf = CertificateFactory.getInstance("X.509");
			CAcert = (X509Certificate) cf.generateCertificate(fis);
			key = CAcert.getPublicKey();

			while (!connectionSocket.isClosed()) {

				int packetType = fromClient.readInt();

				// String testString3 = "";
				if (packetType == 0) {
					int numBytes = fromClient.readInt();
					byte[] clientIP = new byte[numBytes];
					fromClient.readFully(clientIP, 0, numBytes);
					// System.out.println("\nQuery from IP: " + new String(clientIP));

					// TODO after the connection is established, send a hellow message.
					ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ipconfig getifaddr en0");
					// pb.redirectOutput(Redirect.INHERIT);
					pb.redirectError(Redirect.INHERIT);
					Process p = pb.start();

					// for reading the ouput from stream
					BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
					String s = null;
					String terminalOutput = "";
					while ((s = stdInput.readLine()) != null) {
						terminalOutput += s;
						terminalOutput += '\n';
					}
					// System.out.println(terminalOutput);
					// System.out.println(serverHelloMessage + terminalOutput.trim());

					// encrypt the client ip with the private key
					byte[] encryptedClientIP = EncryptandDecrypt.encryption(new String(clientIP), "private");

					// send back to the client
					toClient.writeInt(0);
					toClient.writeInt(encryptedClientIP.length);
					toClient.write(encryptedClientIP);
					// System.out.println("Server sent: " + encryptedClientIP);

				} else if (packetType == 1) {
					/* send enrypted nonce */
					int nonceSize = fromClient.readInt();
					// System.out.println("check int: " + nonceSize);
					byte[] nonce = new byte[nonceSize];
					fromClient.readFully(nonce);
					String nonce64Format = Base64.getEncoder().encodeToString(nonce);
					// System.out.println("check: " + nonce64Format);
					// String nonce64Format = Base64.getEncoder().encodeToString(nonce);
					// System.out.println("Received nonce: " + nonce64Format);
					byte[] encryptedNonce = EncryptandDecrypt.encryptionByte(nonce, "private");
					toClient.writeInt(1);
					toClient.writeInt(encryptedNonce.length);
					toClient.write(encryptedNonce);
					// System.out.println("Encrypted nonce: " + encryptedNonce);

					/* send cert */
					byte[] certData = Files.readAllBytes(certPath);
					// toClient.writeInt(2);
					toClient.writeInt(certData.length);
					toClient.write(certData);
					// System.out.println(certData);
					// System.out.println("Encrypted nonce and cert sent");

					// ANCHOR receiving file from client
				} else if (packetType == 2) {
					System.out.println("Receiving files from client...");
					int numBytes = fromClient.readInt();
					byte[] filename = new byte[numBytes];
					// Must use read fully!
					// See:
					// https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);
					fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				} else if (packetType == 3) {
					// System.out.println("---------------------------------------------------------");
					int encryptedBufferSize = fromClient.readInt();
					int numBytes = fromClient.readInt();
					byte[] block = new byte[encryptedBufferSize];
					fromClient.readFully(block, 0, encryptedBufferSize);
					// TODO 
					byte[] decryptedBlock = ServerDecryptionByte(block, "public", desKey);
					// testString3 += new String(decryptedBlock);
					if (numBytes > 0) {
						bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);
						bufferedFileOutputStream.flush();
					}
					if (numBytes < 117) {
						if (bufferedFileOutputStream != null)
							bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null)
							fileOutputStream.close();
					}
					/*
					 * TODO condition for close server fromClient.close(); toClient.close();
					 * connectionSocket.close();
					 */
				} else if(packetType == 4){
					// System.out.println("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$");
					// get the key
					int desKeyBytesLength = fromClient.readInt();
					byte[] keyByteBuffer = new byte[desKeyBytesLength];
					fromClient.readFully(keyByteBuffer, 0, desKeyBytesLength);
					desKey = new SecretKeySpec(keyByteBuffer, 0, keyByteBuffer.length, "DES");
					// System.out.println("---->" + new String(keyByteBuffer) + "<----");


				}
				// System.out.println(testString3);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static byte[] ServerDecryptionByte(byte[] inputData, String keyType, SecretKey desKey) throws Exception {
		final Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

		if (keyType == "public") {

			// cipher init
			cipher.init(Cipher.DECRYPT_MODE, desKey);

			byte[] encryptedBytesArray = cipher.doFinal(inputData);

			return encryptedBytesArray;
		} else if (keyType == "private") {
			// PrivateKey key = PrivateKeyReader.get(privateKeyPath);

			// // cipher init
			// cipher.init(Cipher.ENCRYPT_MODE, key);

			// byte[] encryptedBytesArray = cipher.doFinal(inputData);

			return null;
		} else {
			System.out.println("Invalid key type");
			return null;
		}
	}
}
