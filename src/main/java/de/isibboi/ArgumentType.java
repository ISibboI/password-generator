package de.isibboi;

public enum ArgumentType {
	LENGTH, ROUNDS, CHARS, GROUP, EXCLUDE, AMOUNT, ALGORITHM;
	
	public static ArgumentType getCommand(char c) {
		switch (c) {
		case 'l': return LENGTH;
		case 'r': return ROUNDS;
		case 'c': return CHARS;
		case 'g': return GROUP;
		case 'e': return EXCLUDE;
		case 'n': return AMOUNT;
		case 'a': return ALGORITHM;
		default: return null;
		}
	}
}