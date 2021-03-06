import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;

import java.lang.ProcessBuilder.Redirect;

public class ClientCP1 {


	private static final String publicKeyPath = "./certMac/public_key.der";
	private static final String privateKeyPath = "./certMac/private_key.der";
	private static String[] userInputToken;
	public static void main(String[] args) {

		String filename = null;
    	// if (args.length > 0) filename = args[0];

		String serverAddress = "localhost";
		if (args.length > 1) filename = args[1];

		int port = 4321;
		if (args.length > 2) port = Integer.parseInt(args[2]);

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;
		
		InputStream fis = null;
		CertificateFactory cf = null;
		X509Certificate CAcert = null;

		X509Certificate serverCert = null;

		PublicKey serverPublicKey = null;


		long timeStarted = System.nanoTime();

		try {

			System.out.println("Establishing connection to server...");

			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			fis = new FileInputStream("./cert/cacse.crt");
			cf = CertificateFactory.getInstance("X.509");
			CAcert =(X509Certificate)cf.generateCertificate(fis);
			PublicKey caPublicKey = CAcert.getPublicKey();

			byte[] encryptedNonce = null;
			String nonce64Format = null;
			boolean enterShell = false;

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
			System.out.println(terminalOutput);

			toServer.writeInt(0);
			toServer.writeInt(terminalOutput.trim().getBytes().length);
			toServer.write(terminalOutput.trim().getBytes());

			boolean done = false;
			while(!done) {
				int packetType = fromServer.readInt();

				if (packetType == 0) {
					int reply = fromServer.readInt();
					byte[] serverReply = new byte[reply];
					fromServer.readFully(serverReply);
					String decryptedReply = EncryptandDecrypt.decryption(serverReply, "public");
					// System.out.println("Decrypted: " + decryptedReply);
					
					toServer.writeInt(1);
					SecureRandom sr = new SecureRandom();
					byte[] nonce = new byte[64];
					sr.nextBytes(nonce);
					toServer.writeInt(64);
					toServer.write(nonce);
					nonce64Format = Base64.getEncoder().encodeToString(nonce);
					// System.out.println("Sent: " + nonce64Format);
				} else if (packetType == 1) {
					/* Received encrypted nonce from server */
					int EncryptednonceSize = fromServer.readInt();
					encryptedNonce = new byte[EncryptednonceSize];
					fromServer.readFully(encryptedNonce, 0, EncryptednonceSize);
					// System.out.println("Encrypted Nonce: " + encryptedNonce);
					/* Receive cert from server */
					int certSize = fromServer.readInt();
					byte[] cert = new byte[certSize];
					fromServer.readFully(cert, 0, certSize);
					// System.out.println("Cert: " + new String(cert));

					/* verify the cert */
					CertificateFactory serverCf = CertificateFactory.getInstance("X.509");
					InputStream certInput = new ByteArrayInputStream(cert);
					serverCert = (X509Certificate) serverCf.generateCertificate(certInput);
					serverCert.verify(caPublicKey);
					System.out.println("The cert is valid!");

					/* Extract public key from server cert */
					Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					serverPublicKey = serverCert.getPublicKey();
					dcipher.init(Cipher.DECRYPT_MODE, serverPublicKey);
					byte[] decryptedNonce = dcipher.doFinal(encryptedNonce);
					String decryptedNoncebase64format = Base64.getEncoder().encodeToString(decryptedNonce);
					// System.out.println("Decrypted nonce: " + decryptedNoncebase64format);

					if (decryptedNoncebase64format.equals(nonce64Format)) {
						System.out.println("The server is correct!");
						done = ClientCP1.Upload(toServer, serverPublicKey, clientSocket);
					} else {
						System.out.println("The server is not valid!");
						break;
					}
				}
			}
			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}

	/**
	 * the shell
	 * @param toServer
	 * @param serverPublicKey
	 * @throws Exception
	 */
	public static boolean Upload(DataOutputStream toServer, PublicKey serverPublicKey, Socket clientSocket) throws Exception {
		BufferedInputStream bufferedFileInputStream = null;
		FileInputStream fileInputStream = null;
		System.out.println("Use 'UPLOAD' to start transferring files!");
		System.out.println(">>> ");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String userOutput = null;
		String userInput = br.readLine();
		ArrayList<String> availableFiles = new ArrayList<String>();

		while (!userInput.equals("EXIT")) {
			System.out.println(">>> ");
			userOutput = userInput;
			
			userInputToken = userInput.split(" ");
			// ANCHOR print available files to send
			ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "ls");
			// pb.redirectOutput(Redirect.INHERIT);
			pb.redirectError(Redirect.INHERIT);
			Process p = pb.start();
			// save the output
			// for reading the ouput from stream
			BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String s = null;
			String terminalOutput = "";
			while ((s = stdInput.readLine()) != null) {
				availableFiles.add(s);
				terminalOutput += s;
				terminalOutput += '\n';
			}
			System.out.println(terminalOutput);
			
			if(userInputToken[0].equals("UPLOAD") && userInputToken.length == 1){
				System.out.println("\u001B[31m" + "Error " + "\u001B[0m" + ": No file selected!");
			} else if (userOutput.length() >= 6 && userOutput.substring(0, 6).equals("UPLOAD") && Arrays.stream(availableFiles.toArray()).anyMatch(userInputToken[1]::equals)) {
				// timer start
				long startTime = System.nanoTime();

				String contents = userOutput.substring(7);
				ArrayList<String> files = new ArrayList<String>(Arrays.asList(contents.split(" ")));

				for (int j = 0; j < files.size(); j++) {
					System.out.println(files.get(j));
				}

				// Send the filename
				String f = files.get(0);
				System.out.println("files: " + f);
				toServer.flush();
				toServer.writeInt(2);
				toServer.writeInt(f.getBytes().length);
				toServer.write(f.getBytes());
				// toServer.flush();
		
				// Open the file
				fileInputStream = new FileInputStream(f);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);
		
				byte [] fromFileBuffer = new byte[117];
				
				// String fileToSend = readFile(f, Charset.defaultCharset());
				// TODO fix the key to use the CA key
				// byte[] encryptedFile = EncryptandDecrypt.encryption(fileToSend, "public");
				// String dencryptedFile = EncryptandDecrypt.decryption(encryptedFile, "public");
				// System.out.println(dencryptedFile);
				// String testString = "";
				// Send the file
				for (boolean fileEnded = false; !fileEnded;) {
					int numBytes = bufferedFileInputStream.read(fromFileBuffer);
					byte[] encryptedBuffer = ClientEncryptionByte(fromFileBuffer, "public", serverPublicKey);
					// testString += EncryptandDecrypt.decryption(encryptedBuffer, "private");
					fileEnded = numBytes < 117;
					toServer.writeInt(3);
					toServer.writeInt(encryptedBuffer.length);
					toServer.writeInt(numBytes);
					toServer.write(encryptedBuffer);
					toServer.flush();
				}
				// System.out.println(testString);
				// System.out.println(fileToSend);
				// toServer.writeInt(3);
				// toServer.writeInt(fileToSend.getBytes().length);
				// toServer.write(fileToSend.getBytes());
				// toServer.flush();
				bufferedFileInputStream.close();
				fileInputStream.close();
				System.out.println("Sending file...");
				// timer end
				long endTime = System.nanoTime();
				System.out.println("\u001B[34m" + "Time" + "\u001B[0m" + " take to upload this file: " + (endTime - startTime)/1000000 + "ms");
			} else if(userInputToken[0].equals("UPLOAD") && !availableFiles.contains(userInputToken[1])){
				System.out.println("\u001B[31m" + "Error " + "\u001B[0m" + ": File doesn't exits!");
			} else {
				System.out.println("Invalid command!");
			}
			System.out.println(">>> ");
			userInput = br.readLine();
			userOutput = userInput;
		}
		toServer.writeInt(4);
		return true;
	}
	
	static String readFile(String path, Charset encoding) throws IOException {
		byte[] encoded = Files.readAllBytes(Paths.get(path));
		return new String(encoded, encoding);
	}

	private static byte[] ClientEncryptionByte(byte[] inputData, String keyType, PublicKey theKey) throws Exception {
		final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		if (keyType == "public") {

			// cipher init
			cipher.init(Cipher.ENCRYPT_MODE, theKey);

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
}
