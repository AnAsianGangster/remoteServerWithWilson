import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
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
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.lang.ProcessBuilder.Redirect;

public class ClientCP2 {


	private static final String publicKeyPath = "./certMac/public_key.der";
	private static final String privateKeyPath = "./certMac/private_key.der";
	public static void main(String[] args) {

		String filename = null;
    	// if (args.length > 0) filename = args[0];

		String serverAddress = "localhost";
		if (args.length > 1) filename = args[1];

		int port = 4321;
		if (args.length > 2) port = Integer.parseInt(args[2]);

		int numBytes = 0;

		Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

		FileInputStream fileInputStream = null;
		BufferedInputStream bufferedFileInputStream = null;
		
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

			while(true) {
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
						enterShell = true;

						/* generate session key */
						SecretKey sessionKey = KeyGenerator.getInstance("DES").generateKey();
						String encodedKey = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
						byte[] encodedKeyByte = encodedKey.trim().getBytes();
						toServer.writeInt(encodedKeyByte.length);
						toServer.write(encodedKeyByte);
						System.out.println("Session key sent!");

						System.out.println("Use 'UPLOAD' to start transferring files!");
						System.out.println(">>> ");
						Scanner sc = new Scanner(System.in);
						String userOutput = null;
						String userInput = sc.nextLine();
						while (!userInput.equals("exit")) {
							System.out.println(">>> ");
							System.out.println("Here we go again");
							userOutput = userInput;
							if (userOutput.length() >= 6 && userOutput.substring(0, 6).equals("UPLOAD")) {
								String contents = userOutput.substring(7);
								ArrayList<String> files = new ArrayList<String>(Arrays.asList(contents.split(" ")));
			
								for (int j = 0; j < files.size(); j++) {
									System.out.println(files.get(j));
								}
			
								// Send the filename
								String f = files.get(0);
								System.out.println("files: " + f);
								toServer.writeInt(2);
								toServer.writeInt(f.getBytes().length);
								toServer.write(f.getBytes());
								// toServer.flush();
						
								// Open the file
								fileInputStream = new FileInputStream(f);
								bufferedFileInputStream = new BufferedInputStream(fileInputStream);
						
								byte [] fromFileBuffer = new byte[117];
								Cipher cipher = Cipher.getInstance("DES");
								cipher.init(Cipher.ENCRYPT_MODE, sessionKey);
								byte[] encryptedfromFileBuffer = null;
						
								// Send the file
								for (boolean fileEnded = false; !fileEnded;) {
									encryptedfromFileBuffer = cipher.doFinal(fromFileBuffer);
									numBytes = bufferedFileInputStream.read(encryptedfromFileBuffer);
									fileEnded = numBytes < 117;

						
									toServer.writeInt(3);
									toServer.writeInt(numBytes);
									toServer.write(encryptedfromFileBuffer);
									toServer.flush();
								}
								System.out.println("Sending file...");
								System.out.println(">>> ");
								userInput = sc.nextLine();
								userOutput = userInput;
							} else {
								System.out.println("Invalid command!");
								System.out.println(">>> ");
								userInput = sc.nextLine();

							}
						}

						/* exit the services */
						String exitMessage = "exit";
						byte[] exitMessageByte = exitMessage.trim().getBytes();
						if (fromServer != null) {
							toServer.writeInt(4);
							toServer.writeInt(exitMessageByte.length);
							toServer.write(exitMessageByte);
							if (bufferedFileInputStream != null) {
								bufferedFileInputStream.close();
							}
							if (fileInputStream != null) {
								fileInputStream.close();
							}
							break;
						} 
					} else {
						System.out.println("The server is not valid!");
						break;
					}
				}
			}

			/*
			System.out.println("Use 'UPLOAD' to start transferring files!");
			System.out.println(">>> ");
			Scanner sc = new Scanner(System.in);
			String userOutput = null;
			String userInput = sc.nextLine();
			while (!userInput.equals("exit")) {
				System.out.println(">>> ");
				userOutput = userInput;
				if (userOutput.length() >= 7 && userOutput.substring(0, 6).equals("UPLOAD")) {
					String contents = userOutput.substring(7);
					ArrayList<String> files = new ArrayList<String>(Arrays.asList(contents.split(" ")));

					for (int j = 0; j < files.size(); j++) {
						System.out.println(files.get(j));
					}

					// Send the filename
					String f = files.get(0);
					System.out.println("files: " + f);
					toServer.writeInt(2);
					toServer.writeInt(f.getBytes().length);
					toServer.write(f.getBytes());
					// toServer.flush();
			
					// Open the file
					fileInputStream = new FileInputStream(f);
					bufferedFileInputStream = new BufferedInputStream(fileInputStream);
			
					byte [] fromFileBuffer = new byte[117];
					Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					PublicKey serverPublicKey = PublicKeyReader.get("./cert/public_key.der");
					cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
					byte[] encryptedfromFileBuffer = cipher.doFinal(fromFileBuffer);
			
					// Send the file
					for (boolean fileEnded = false; !fileEnded;) {
						numBytes = bufferedFileInputStream.read(encryptedfromFileBuffer);
						fileEnded = numBytes < 117;
			
						toServer.writeInt(3);
						toServer.writeInt(numBytes);
						toServer.write(encryptedfromFileBuffer);
						toServer.flush();
					}
					System.out.println(encryptedfromFileBuffer);
					System.out.println("Sending file...");
					bufferedFileInputStream.close();
					fileInputStream.close();
					break;
				} else {
					System.out.println("Invalid command!");
					System.out.println(">>> ");
					userInput = sc.nextLine();
				}
			}
			*/
			System.out.println("Closing connection...");

		} catch (Exception e) {e.printStackTrace();}

		long timeTaken = System.nanoTime() - timeStarted;
		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}
}

/*
class ClientProcess extends Thread {
	String f;
	String serverAddress = "localhost";
	int port = 4321;
	Socket clientSocket = null;
	DataOutputStream toServer = null;
	DataInputStream fromServer = null;
	int numBytes = 0;

	FileInputStream fileInputStream = null;
	BufferedInputStream bufferedFileInputStream = null;
	ClientProcess(String f, Socket clientSocket, DataOutputStream toServer, DataInputStream fromServer, int numBytes) {
		this.f = f;
		this.clientSocket = clientSocket;
		this.toServer = toServer;
		this.fromServer = fromServer;
		this.numBytes = numBytes;
	}

	@Override
	public void run() {
		try {
			toServer.writeInt(2);
			toServer.writeInt(f.getBytes().length);
			toServer.write(f.getBytes());
			// toServer.flush();
	
			// Open the file
			fileInputStream = new FileInputStream(f);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);
	
			byte [] fromFileBuffer = new byte[117];
	
			// Send the file
			for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117;
	
				toServer.writeInt(3);
				toServer.writeInt(numBytes);
				toServer.write(fromFileBuffer);
				toServer.flush();
			}
			System.out.println("check");
			bufferedFileInputStream.close();
			fileInputStream.close();
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}
*/
