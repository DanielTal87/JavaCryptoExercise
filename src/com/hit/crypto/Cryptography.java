package com.hit.crypto;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import static java.lang.System.exit;

public class Cryptography
{
	final private static File fileAfterEncryption = new File("src/com/hit/resource/encryptOutput.txt");
	final private static File fileAfterDecryption = new File("src/com/hit/resource/decryptOutput.txt");
	final private static File aliceKeystore = new File("src/com/hit/resource/aliceKeystore.jks");
	final private static File bobKeystore = new File("src/com/hit/resource/bobKeystore.jks");
	final private static File configFile = new File("src/com/hit/resource/config.txt");

	private static File inputFile;
	private static String inputProviderForFile;
	private static String inputProviderForKey;
	private static String inputAlgorithmForFileEncryption;
	private static String inputAlgorithmMode;
	private static String inputAlgorithmPadding;
	private static String inputAlgorithmForKeyEncryption;

	private static String keystorePassword;
	private static String privateKeyAlias;
	private static String privateKeyPassword;
	private static String publicCertificateAlias;

	public static void main(String[] args)
	{
		BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
		try
		{
			System.out.println("Please enter the full path of your input file");
			String inputPath = input.readLine();
			inputFile = new File(inputPath);

			/* inputs for file encryption and decryption */
			System.out.println("Please enter the provider for file encryption (SunJCE, etc), or 'non' for default provider");
			inputProviderForFile = input.readLine();
			System.out.println("Please enter the cipher algorithm name for file encryption (AES, DES, etc)");
			inputAlgorithmForFileEncryption = input.readLine();
			System.out.println("Please enter the cipher algorithm mode (CBC, ECB, etc)");
			inputAlgorithmMode = input.readLine();
			System.out.println("Please enter the cipher algorithm padding (PKCS5Padding, etc)");
			inputAlgorithmPadding = input.readLine();

			/* input for key encryption and decryption */
			System.out.println("Please enter the cipher algorithm name for key encryption (RSA, etc)");
			inputAlgorithmForKeyEncryption = input.readLine();
			System.out.println("Please enter the provider for key encryption, or 'non' for default provider");
			inputProviderForKey = input.readLine();

			/* The user input values for encryption */
			System.out.println("Please enter the keystore password at encryption mode");
			keystorePassword = input.readLine();
			System.out.println("Please enter the alias for private key at encryption mode");
			privateKeyAlias = input.readLine();
			System.out.println("Please enter the password for private key at encryption mode");
			privateKeyPassword = input.readLine();
			System.out.println("Please enter the alias for the other side public key at encryption mode");
			publicCertificateAlias = input.readLine();

			System.out.println("Begin the encryption process..");
			int[] size = encrypt(inputFile, aliceKeystore);
			System.out.println("Encryption Succeeded!\n");

			/* The user input values for decryption */
			System.out.println("Please enter the keystore password at decryption mode");
			keystorePassword = input.readLine();
			System.out.println("Please enter the alias for private key at decryption mode ");
			privateKeyAlias = input.readLine();
			System.out.println("Please enter the password for private key at decryption mode");
			privateKeyPassword = input.readLine();
			System.out.println("Please enter the alias for the other side public key at decryption mode");
			publicCertificateAlias = input.readLine();
			input.close();

			System.out.println("Begin the decryption process..");
			decrypt(fileAfterEncryption, configFile, bobKeystore, size);
			System.out.println("Decryption Succeeded\n");
			System.out.println("Done..");
			exit(0);

		} catch (IOException e)
		{
			System.err.println("ERROR, wrong input");
			e.printStackTrace();
		}

	}

	/**
	 * The function receives a file and all encryption utils, encrypt the 'fileToEncrypt' file and create the configuration file
	 *
	 * @param fileToEncrypt a file for encryption uses
	 * @param keystoreFile  keystore file that contains the user's public and private key and the other's public key
	 * @return an array that contains the element sizes
	 */
	private static int[] encrypt(File fileToEncrypt, File keystoreFile)
	{

		SecretKey symmetricKey = createSymmetricKey();
		AlgorithmParameters algoParams = fileEncryption(fileToEncrypt, symmetricKey, fileAfterEncryption);
		return createConfigurationFile(fileToEncrypt, configFile, keystoreFile, symmetricKey, algoParams);
	}

	/**
	 * The function receives a file and all decryption utils, decrypt the 'fileToDecrypt' file and create the configuration file
	 *
	 * @param fileToDecrypt a file for decryption uses
	 * @param configFile    the configuration file
	 * @param keystoreFile  keystore file that contains the user's public and private key and the other's public key
	 * @param elementsSizes an array that contains the: IV, signature and the encrypt key sizes
	 */
	private static void decrypt(File fileToDecrypt, File configFile, File keystoreFile, int[] elementsSizes)
	{
		byte[] signature = new byte[elementsSizes[0]];
		byte[] encryptKey = new byte[elementsSizes[1]];
		byte[] encodedAlgoParams = new byte[elementsSizes[2]];
		byte[] signatureAlgoArray = new byte[elementsSizes[3]];

		getElementsFromConfigFile(signature, encryptKey, encodedAlgoParams, signatureAlgoArray, configFile);

		String signatureAlgo = new String(signatureAlgoArray);
		AlgorithmParameters algoParams = null;
		try
		{
			algoParams = AlgorithmParameters.getInstance(inputAlgorithmForFileEncryption);
			algoParams.init(encodedAlgoParams);
		} catch (NoSuchAlgorithmException | IOException e)
		{
			e.printStackTrace();
		}

		KeyPair keyPair = getKeyPair(keystoreFile);
		Key symKey = decryptSymmetricKey(keyPair, encryptKey);

		byte[] decryptData = decryptFileContent(algoParams, symKey, fileToDecrypt);
		verifyDigitalSignature(decryptData, signature, keyPair, signatureAlgo);
	}


	/**
	 * @param keystoreFile keystore file that contains the user's public and private key and the other's public key
	 * @return a key-pair that contains a public key and a private key
	 */
	private static KeyPair getKeyPair(File keystoreFile)
	{
		PublicKey publicKey = null;
		PrivateKey privateKey = null;

		try
		{
			KeyStore keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(keystoreFile), keystorePassword.toCharArray());
			privateKey = (PrivateKey) keyStore.getKey(privateKeyAlias, privateKeyPassword.toCharArray());
			publicKey = keyStore.getCertificate(publicCertificateAlias).getPublicKey();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | UnrecoverableKeyException e)
		{
			e.printStackTrace();
		}

		return new KeyPair(publicKey, privateKey);

	}

	/**
	 * The function creates a 128-bit secret key
	 *
	 * @return the secretKey if succeeded, null otherwise
	 */
	private static SecretKey createSymmetricKey()
	{
		SecretKey secretKey = null;

		try
		{
			KeyGenerator keyGen = KeyGenerator.getInstance(inputAlgorithmForFileEncryption);
			keyGen.init(128);
			secretKey = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}

		return secretKey;
	}

	/**
	 * The function signing the input file
	 *
	 * @param keyPair            a key-pair that contains a public key and a private key
	 * @param path               the input file path
	 * @param signatureAlgorithm an algorithm for signature creation
	 * @return a byte array that contains thr signature if succeeded, null otherwise
	 */
	private static byte[] sign(KeyPair keyPair, Path path, String signatureAlgorithm)
	{
		byte[] signature = null;

		try
		{
			byte[] dataFromFile = Files.readAllBytes(path);
			Signature sign = Signature.getInstance(signatureAlgorithm);
			sign.initSign(keyPair.getPrivate());
			sign.update(dataFromFile);
			signature = sign.sign();
		} catch (IOException | InvalidKeyException | NoSuchAlgorithmException | SignatureException e)
		{
			e.printStackTrace();
		}

		return signature;
	}

	/**
	 * The function encrypt the 'fileToEncrypt' file
	 *
	 * @param fileToEncrypt    the file that the function needs to encrypt
	 * @param symmetricKey     a symmetric key
	 * @param fileAfterEncrypt a file after the encryption
	 */
	private static AlgorithmParameters fileEncryption(File fileToEncrypt, SecretKey symmetricKey, File fileAfterEncrypt)
	{
		CipherOutputStream cipherOutputStream = null;
		AlgorithmParameters algoParams = null;
		Cipher cipher;

		try
		{
			if (inputProviderForFile.equals("non"))
			{
				cipher = Cipher.getInstance(inputAlgorithmForFileEncryption + "/" + inputAlgorithmMode + "/" + inputAlgorithmPadding);
			}
			else
			{
				cipher = Cipher.getInstance(inputAlgorithmForFileEncryption + "/" + inputAlgorithmMode + "/" + inputAlgorithmPadding, inputProviderForFile);
			}
			if (cipher != null && symmetricKey != null)
			{
				cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
				cipherOutputStream = new CipherOutputStream(new FileOutputStream(fileAfterEncrypt), cipher);
				Path path = Paths.get(fileToEncrypt.getPath());
				byte[] dataFromFile = Files.readAllBytes(path);
				cipherOutputStream.write(dataFromFile);
				algoParams = cipher.getParameters();
			}
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException | NoSuchProviderException e2)
		{
			e2.printStackTrace();
		} finally
		{
			try
			{
				if (cipherOutputStream != null)
				{
					cipherOutputStream.flush();
					cipherOutputStream.close();
				}
			} catch (IOException e)
			{
				e.printStackTrace();
			}
		}

		return algoParams;
	}

	/**
	 * The function recives all the utils that needed to create the configuration file and adds all the configuration to the 'configFile'
	 *
	 * @param fileToEncrypt   a file for encryption uses
	 * @param configFile      the configuration file
	 * @param keystoreFile    keystore file that contains the user's public and private key and the other's public key
	 * @param symmetricKey    a symmetric key
	 * @param algorithmParams contains all the parameters that needed to create the configuration file
	 * @return an array of the elements sizes if succeeded, null otherwise
	 */
	private static int[] createConfigurationFile(File fileToEncrypt, File configFile, File keystoreFile, SecretKey symmetricKey, AlgorithmParameters algorithmParams)
	{
		int[] elementsSizes = new int[4];
		KeyPair keyPair = getKeyPair(keystoreFile);
		String signatureAlgo = "SHA256withRSA";

		// create signature to the encrypt file
		Path path = Paths.get(fileToEncrypt.getPath());
		byte[] sign = sign(keyPair, path, signatureAlgo);

		// encrypt symmetric key, using 'inputAlgorithmForKeyEncryption' algorithm
		if (symmetricKey != null)
		{
			FileOutputStream fileOutputStream = null;
			Cipher cipherAsymmetric;

			try
			{
				fileOutputStream = new FileOutputStream(configFile);

				if (inputProviderForKey.equals("non"))
				{
					cipherAsymmetric = Cipher.getInstance(inputAlgorithmForKeyEncryption);
				}
				else
				{
					cipherAsymmetric = Cipher.getInstance(inputAlgorithmForKeyEncryption, inputProviderForKey);
				}
				cipherAsymmetric.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
				byte[] encryptKey = cipherAsymmetric.doFinal(symmetricKey.getEncoded());

				fileOutputStream.write(algorithmParams.getEncoded());
				fileOutputStream.write(sign);
				fileOutputStream.write(encryptKey);
				fileOutputStream.write(signatureAlgo.getBytes());

				elementsSizes[0] = sign.length;
				elementsSizes[1] = encryptKey.length;
				elementsSizes[2] = algorithmParams.getEncoded().length;
				elementsSizes[3] = signatureAlgo.length();
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException | InvalidKeyException e)
			{
				e.printStackTrace();
			} finally
			{
				try
				{
					if (fileOutputStream != null)
					{
						fileOutputStream.flush();
						fileOutputStream.close();
					}
				} catch (IOException e)
				{
					e.printStackTrace();
				}
			}
		}

		return elementsSizes;
	}

	/**
	 * @param decryptText        the decrypt text
	 * @param sign               a signature to the encrypt file
	 * @param key                a key-pair that contains a public key and a private key
	 * @param signatureAlgorithm an algorithm for signature creation
	 * @return true if the signature was verified, false otherwise
	 */
	private static boolean verify(byte[] decryptText, byte[] sign, KeyPair key, String signatureAlgorithm)
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException
	{
		Signature signature = Signature.getInstance(signatureAlgorithm);
		signature.initVerify(key.getPublic());
		signature.update(decryptText);

		return signature.verify(sign);
	}

	/**
	 * @param sign               a signature to the encrypt file
	 * @param encryptKey         a byte array that contains the encrypt key
	 * @param encodedAlgoParams  a byte array that contains the encoded algorithm parameters
	 * @param signatureAlgoArray a byte array that contains the signature algorithm
	 * @param configFile         the configuration file
	 */
	private static void getElementsFromConfigFile(byte[] sign, byte[] encryptKey, byte[] encodedAlgoParams, byte[] signatureAlgoArray, File configFile)
	{
		FileInputStream fileInputStream = null;

		try
		{
			fileInputStream = new FileInputStream((configFile));
			fileInputStream.read(encodedAlgoParams);
			fileInputStream.read(sign);
			fileInputStream.read(encryptKey);
			fileInputStream.read(signatureAlgoArray);

		} catch (IOException e1)
		{
			e1.printStackTrace();
		} finally
		{
			try
			{
				if (fileInputStream != null)
				{
					fileInputStream.close();
				}
			} catch (IOException e)
			{
				e.printStackTrace();
			}
		}
	}

	/**
	 * @param keyPair    a key-pair that contains a public key and a private key
	 * @param encryptKey a byte array that contains the encrypt key
	 * @return a secret key
	 */
	private static Key decryptSymmetricKey(KeyPair keyPair, byte[] encryptKey)
	{
		Key secretKey = null;
		Cipher cipherAsy;
		try
		{

			if (inputProviderForKey.equals("non"))
			{
				cipherAsy = Cipher.getInstance(inputAlgorithmForKeyEncryption);
			}
			else
			{
				cipherAsy = Cipher.getInstance(inputAlgorithmForKeyEncryption, inputProviderForKey);
			}
			cipherAsy.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			secretKey = new SecretKeySpec(cipherAsy.doFinal(encryptKey), inputAlgorithmForFileEncryption);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchProviderException e1)
		{
			e1.printStackTrace();
		}
		return secretKey;
	}

	/**
	 * @param algorithmParams contains all the parameters that needed for the file decryption
	 * @param secretKey       a secret key
	 * @param fileToDecrypt   the file that the function will decrypt
	 * @return a byte array that contains decrypt data if succeeded, null otherwise
	 */
	private static byte[] decryptFileContent(AlgorithmParameters algorithmParams, Key secretKey, File fileToDecrypt)
	{
		byte[] decryptData = null;
		Cipher cipher;
		try
		{
			if (inputProviderForFile.equals("non"))
			{
				cipher = Cipher.getInstance(inputAlgorithmForFileEncryption + "/" + inputAlgorithmMode + "/" + inputAlgorithmPadding);
			}
			else
			{
				cipher = Cipher.getInstance(inputAlgorithmForFileEncryption + "/" + inputAlgorithmMode + "/" + inputAlgorithmPadding, inputProviderForFile);
			}
			cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParams);
			FileInputStream fileInputStream = new FileInputStream(fileToDecrypt);
			CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);

			List<Byte> values = new ArrayList<>();
			int nextByte;
			while ((nextByte = cipherInputStream.read()) != -1)
			{
				values.add((byte) nextByte);
			}

			decryptData = new byte[values.size()];
			for (int i = 0; i < decryptData.length; i++)
			{
				decryptData[i] = values.get(i);
			}
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchProviderException e1)
		{
			e1.printStackTrace();
		}

		return decryptData;

	}

	/**
	 * The function verifies the digital signature and writes the decrypt data if the verification passed, write an error otherwise
	 *
	 * @param decryptData        a byte array the contains the decrypt data
	 * @param sign               a signature to the encrypt file
	 * @param keyPair            a key-pair that contains a public key and a private key
	 * @param signatureAlgorithm an algorithm for signature creation
	 */

	private static void verifyDigitalSignature(byte[] decryptData, byte[] sign, KeyPair keyPair, String signatureAlgorithm)
	{
		BufferedWriter outputBuffer = null;

		try
		{
			boolean verify = verify(decryptData, sign, keyPair, signatureAlgorithm);
			outputBuffer = new BufferedWriter(new FileWriter(fileAfterDecryption));

			if (verify)
			{
				outputBuffer.write(new String(decryptData));
			}
			else
			{
				outputBuffer.write("Error,attack");
				System.err.println("Error,attack");
			}
		} catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException | IOException e)
		{
			e.printStackTrace();
		} finally
		{
			try
			{
				if (outputBuffer != null)
				{
					outputBuffer.flush();
					outputBuffer.close();
				}
			} catch (IOException e)
			{
				e.printStackTrace();
			}
		}
	}
}

