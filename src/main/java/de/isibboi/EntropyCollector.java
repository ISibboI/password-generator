package de.isibboi;

import java.security.MessageDigest;
import java.security.SecureRandom;

public class EntropyCollector implements Runnable {
	private volatile boolean isRunning;
	private volatile boolean isFinished;
	private volatile Thread executor;
	private final Object lock = new Object();

	private final long amount;
	private final MessageDigest digest;

	private volatile int bytesLeft;
	private volatile byte[] result;

	public EntropyCollector(int bytes, MessageDigest digest) {
		this.amount = bytes;
		this.bytesLeft = bytes;
		this.digest = digest;
	}

	public void start() {
		synchronized (lock) {
			if (isRunning) {
				throw new IllegalStateException("EntropyCollector was already started.");
			} else if (isFinished) {
				throw new IllegalStateException("EntropyCollector is already finished.");
			} else {
				isRunning = true;
			}

			executor = new Thread(this, "Entropy Collector");
			executor.start();
		}
	}

	public boolean isFinished() {
		return isFinished;
	}

	public boolean isRunning() {
		return isRunning;
	}

	public int bytesLeft() {
		return bytesLeft;
	}

	public byte[] getResult() {
		if (result == null) {
			throw new IllegalStateException("Result is not calculated!");
		} else {
			return result;
		}
	}

	@Override
	public void run() {
		synchronized (lock) {
			if (Thread.currentThread() != executor) {
				throw new IllegalStateException("This object cannot be run with foreign threads.");
			}
		}

		SecureRandom r = new SecureRandom();

		while (bytesLeft > 0) {
			byte[] buffer = r.generateSeed(1);
			bytesLeft--;
			digest.update(buffer);
		}

		result = digest.digest();

		synchronized (lock) {
			isFinished = true;
			isRunning = false;
		}

		synchronized (this) {
			notifyAll();
		}

		executor = null;
	}
}