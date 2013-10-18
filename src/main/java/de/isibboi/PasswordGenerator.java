package de.isibboi;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class PasswordGenerator {
	private static final int DEFAULT_PASSWORD_LENGTH = 8;
	private static final int DEFAULT_PASSWORD_ROUNDS = 2;
	private static final int DEFAULT_PASSWORD_AMOUNT = 1;
	private static final String DEFAULT_HASH_FUNCTION = "SHA";
	private static final String VERSION = "1.2.6";

	private static final Set<Character> characters = new HashSet<>(128);
	private static final Map<String, char[]> charGroups = new HashMap<>();

	private static int length = -1;
	private static int rounds = -1;
	private static int amount = -1;
	private static String algorithm;

	public static void main(String[] args) {
		initCharGroups();

		parseArgs(args);

		char[] allowed = calculateAllowedChars();

		if (length == -1) {
			length = DEFAULT_PASSWORD_LENGTH;
			System.out.println("Length set to: " + length);
		}

		if (rounds == -1) {
			rounds = DEFAULT_PASSWORD_ROUNDS;
			System.out.println("Rounds set to: " + rounds);
		}

		if (amount == -1) {
			amount = DEFAULT_PASSWORD_AMOUNT;
			System.out.println("Amount set to: " + amount);
		}

		if (algorithm == null) {
			algorithm = DEFAULT_HASH_FUNCTION;
			System.out.println("Hash function set to: " + algorithm);
		}

		Collection<String> passwords = generatePasswords(allowed);

		for (String password : passwords) {
			System.out.println(password);
		}
	}

	private static Collection<String> generatePasswords(char[] chars) {
		final char[] password = new char[length];
		MessageDigest digest = null;
		Collection<String> passwords = new ArrayList<>(amount);

		try {
			digest = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			error("No such digest: " + algorithm);
		}

		final int bytes = PasswordGenerator.rounds * digest.getDigestLength();

		final int allBytes = bytes * length * amount;

		int currentBytes = 0;
		DecimalFormat format = new DecimalFormat("##0.00");

		for (int number = 1; number <= amount; number++) {
			System.out.println(" ===== Generating password number " + number + "/" + amount + " =====");
			for (int i = 0; i < length; i++) {
				EntropyCollector collector = new EntropyCollector(bytes, digest);
				collector.start();

				System.out.println(" === Collecting entropy for character " + (i + 1) + "/" + length + " (" + bytes
						+ " bytes) ===");
				int lastBytesLeft = bytes;

				while (!collector.isFinished()) {
					int currentBytesLeft = collector.bytesLeft();
					if (currentBytesLeft != lastBytesLeft) {
						System.out.println("Still needing " + currentBytesLeft + " bytes of entropy. (Overall "
								+ format.format(100.0 * currentBytes / allBytes) + "%)");
						currentBytes += lastBytesLeft - currentBytesLeft;
						lastBytesLeft = currentBytesLeft;
					}

					try {
						synchronized (collector) {
							collector.wait(1000);
						}
					} catch (InterruptedException e) {
						throw new RuntimeException("This should never happen!", e);
					}
				}

				currentBytes += lastBytesLeft;

				BigInteger x = new BigInteger(collector.getResult());
				x = x.mod(BigInteger.valueOf(chars.length));
				password[i] = chars[x.intValue()];
			}

			passwords.add(String.valueOf(password));
		}

		System.out.println(" ===== FINISHED =====");

		return passwords;
	}

	private static char[] calculateAllowedChars() {
		if (characters.size() == 0) {
			addGroup("a-z");
		}

		Set<Character> allowed = new HashSet<Character>(characters);

		char[] result = new char[allowed.size()];
		int i = 0;
		for (char c : allowed) {
			result[i++] = c;
		}

		return result;
	}

	private static void initCharGroups() {
		char[] alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
		char[] lowerLatin = "abcdefghijklmnopqrstuvwxyz".toCharArray();
		char[] upperLatin = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
		char[] numbers = "0123456789".toCharArray();
		char[] alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
		char[] special = "^°!\"§$%&/()=?´`{[]}\\+*~#'-_.:,;><|".toCharArray();
		char[] simpleSpecial = "!\"§$%&/()=?{[]}\\+*#'-_.:,;><|".toCharArray();
		char[] complexSpecial = "^°`´~".toCharArray();
		char[] binary = "01".toCharArray();
		char[] hex = "0123456789abcdef".toCharArray();
		char[] sibbo = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ23456789abcdef0123456789!\"§$%&/()=?{[]}\\+*#'-_.:,;><|"
				.toCharArray();

		charGroups.put("alphabet", alphabet);
		charGroups.put("a-zA-Z", alphabet);
		charGroups.put("alphanumeric", alphanumeric);
		charGroups.put("a-zA-Z0-9", alphanumeric);
		charGroups.put("a-z", lowerLatin);
		charGroups.put("A-Z", upperLatin);
		charGroups.put("0-9", numbers);
		charGroups.put("special", special);
		charGroups.put("simpleSpecial", simpleSpecial);
		charGroups.put("complexSpecial", complexSpecial);
		charGroups.put("01", binary);
		charGroups.put("0x", hex);
		charGroups.put("sibbo", sibbo);

		Set<Character> allSet = new HashSet<>(1024);
		for (char[] chars : charGroups.values()) {
			for (char c : chars) {
				allSet.add(c);
			}
		}

		char[] all = new char[allSet.size()];
		int i = 0;
		for (char c : allSet) {
			all[i++] = c;
		}

		charGroups.put("all", all);
	}

	private static void parseArgs(String[] args) {
		ArgumentType current = null;

		for (String arg : args) {
			if (current == null) {
				if (arg.startsWith("-")) {
					if (arg.equals("--help")) {
						printHelp();
						System.exit(0);
					}

					if (arg.length() == 2) {
						current = ArgumentType.getCommand(arg.charAt(1));
					} else {
						error("Arguments must have a length of 1");
					}
				} else {
					error("Arguments must start with '-'");
				}
			} else {
				switch (current) {
				case GROUP:
					addGroup(arg);
					break;
				case EXCLUDE_GROUP:
					addExcludeGroup(arg);
					break;
				case CHARS:
					addChars(arg);
					break;
				case LENGTH:
					setLength(arg);
					break;
				case ROUNDS:
					setRounds(arg);
					break;
				case EXCLUDE:
					addExcludes(arg);
					break;
				case AMOUNT:
					setAmount(arg);
					break;
				case ALGORITHM:
					setAlgorithm(arg);
					break;
				default:
					throw new RuntimeException("Unknown argument: " + current);
				}

				current = null;
			}
		}
	}

	private static void addExcludeGroup(String arg) {
		char[] group = charGroups.get(arg);

		if (group == null) {
			error("No such character group: " + arg);
		} else {
			for (char c : group) {
				characters.remove(c);
			}
		}
	}

	private static void setAlgorithm(String arg) {
		if (algorithm != null) {
			error("Algorithm must not be set more than one times.");
		}

		algorithm = arg;
	}

	private static void setAmount(String arg) {
		if (amount != -1) {
			error("Amount must not be set more than one times.");
		}

		try {
			amount = Integer.parseInt(arg);
		} catch (NumberFormatException e) {
			error("Could not parse amount: " + arg);
		}

		if (amount <= 0) {
			error("Amount must be greater than zero");
		}
	}

	private static void addExcludes(String arg) {
		for (char c : arg.toCharArray()) {
			characters.remove(c);
		}
	}

	private static void setRounds(String arg) {
		if (rounds != -1) {
			error("Rounds must not be set more than one times.");
		}

		try {
			rounds = Integer.parseInt(arg);
		} catch (NumberFormatException e) {
			error("Could not parse rounds: " + arg);
		}

		if (rounds <= 0) {
			error("Rounds must be greater than zero");
		}

		if (rounds > 1024 * 1024) {
			error("Rounds muust be smaller or equal to " + 1024 * 1024);
		}
	}

	private static void setLength(String arg) {
		if (length != -1) {
			error("Length must not be set more than one times.");
		}

		try {
			length = Integer.parseInt(arg);
		} catch (NumberFormatException e) {
			error("Could not parse length: " + arg);
		}

		if (length <= 0) {
			error("Length must be greater than zero");
		}
	}

	private static void addChars(String arg) {
		for (char c : arg.toCharArray()) {
			characters.add(c);
		}
	}

	private static void addGroup(String arg) {
		char[] group = charGroups.get(arg);

		if (group == null) {
			error("No such character group: " + arg);
		} else {
			for (char c : group) {
				characters.add(c);
			}
		}
	}

	public static void error(String error) {
		System.out.println("Error: " + error);
		printHelp();
		System.exit(-1);
	}

	private static void printHelp() {
		System.out.println("Usage:");
		System.out.println("java -jar PasswordGenerator-" + VERSION + ".jar <args>");
		System.out
				.println("<args> is a list of arguments, marked with - and the corresponding values, separated with space.");
		System.out
				.println("Per default, the password contains lowercase latin letters, if nothing else is specified. If something else is specified, those letters are not necessarily included.");
		System.out
				.println("Characters are added and removed from the set of characters in the same order as you specify the arguments.");

		System.out.println("\nArgument types:");
		System.out.println("-l: Sets the length of the password. (Default: " + DEFAULT_PASSWORD_LENGTH + ")");
		System.out.println("-r: Sets the amount rounds that should be used to calculate one character. (Default: "
				+ DEFAULT_PASSWORD_ROUNDS + ")");
		System.out.println("-c: Adds some chars to the set of chars that are used for the password.");
		System.out.println("-e: Removes some chars from the set of chars that are used for the password.");
		System.out.println("-n: Sets the amount of passwords to generate. (Default: " + DEFAULT_PASSWORD_AMOUNT + ")");
		System.out.println("-g: Adds a character group to the set of chars that are used for the password.");
		System.out.println("-x: Removes a character group from the set of chars that are used for the password.");
		System.out.println("-a: Sets the algorithm to use for hashing (Default: " + DEFAULT_HASH_FUNCTION + ")");

		System.out.println("\nCharacter groups:");
		System.out.println("alphabet, a-zA-Z: Upper and lower case latin letters.");
		System.out.println("alphanumeric, a-zA-Z0-9: Upper and lower case latin letters and numbers.");
		System.out.println("a-z: Lower case latin letters.");
		System.out.println("A-Z: Upper case latin letters.");
		System.out.println("0-9: Numbers.");
		System.out.println("01: Binary.");
		System.out.println("0x: Hex.");
		System.out.println("special: ^°!\"§$%&/()=?´`{[]}\\+*~#'-_.:,;><|");
		System.out.println("simpleSpecial: !\"§$%&/()=?{[]}\\+*#'-_.:,;><|");
		System.out.println("complexSpecial: ^°`´~");
		System.out.println("sibbo: Some characters I like.");
		System.out.println("all: All listed character groups");

		System.out.println("\nAlgorithms:");
		Provider[] providers = Security.getProviders();
		List<String> algorithms = new ArrayList<>();
		for (Provider provider : providers) {
			for (Provider.Service service : provider.getServices()) {
				if (service.getClassName().contains("Digest")) {
					algorithms.add(service.getAlgorithm());
				}
			}
		}

		Collections.sort(algorithms);
		System.out.println(Arrays.toString(algorithms.toArray()));
	}
}
