package com.k2cybersecurity.instrumentator.utils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.lang3.StringUtils;

import com.k2cybersecurity.intcodeagent.filelogging.FileLoggerThreadPool;
import com.k2cybersecurity.intcodeagent.filelogging.LogLevel;
import com.k2cybersecurity.intcodeagent.logging.DeployedApplication;

public class HashGenerator {

	private static final String TMP_DIR = "/tmp/";
	private static final String ERROR2 = "Error : ";
	private static final String TAR_SIZE = "tar size : ";
	private static final String TAR_GZ = "tar.gz";
	private static final String K2_TEMP_DIR = "K2-";
	private static final Set<String> JAVA_APPLICATION_ALLOWED_FILE_EXT = new HashSet<>(
			Arrays.asList(new String[] { "java", "jsp", "class", "jar", "war", "ear" }));
	private static final Set<String> OTHER_CRITICAL_FILE_EXT = new HashSet<>(
			Arrays.asList(new String[] { "htm", "html", "js" }));
	private static final String TWO_PIPES = "||";

	private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
	public static final String SHA_256 = "SHA-256";
	public static final String FILE_FOR_SHA_CALC = "File for SHA calc : ";
	public static final String UNSORTED_SHA_LIST = "Unsorted SHA list : ";
	public static final String SORTED_SHA_LIST = "Sorted SHA list : ";
	public static final String ERROR = "Error :";

	/**
	 * generates hash of a file content according to the algorithm provided.
	 *
	 * @return It returns the hash in string format
	 */
	private static String getChecksum(String data) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance(SHA_256);
			digest.update(data.getBytes());
			byte[] hashedBytes = digest.digest();
			return convertByteArrayToHexString(hashedBytes);
		} catch (NoSuchAlgorithmException e) {
			logger.log(LogLevel.ERROR, ERROR, e, HashGenerator.class.getName());
		}
		return null;
	}

	/**
	 * generates hash of a file content according to the algorithm provided.
	 *
	 * @param file file object whose hash is to be calculated
	 * @return It returns the hash in string format
	 */
	public static String getChecksum(File file) {
		try (FileInputStream inputStream = new FileInputStream(file)) {
			MessageDigest digest = MessageDigest.getInstance(SHA_256);

			byte[] bytesBuffer = new byte[1024];
			int bytesRead = -1;

			while ((bytesRead = inputStream.read(bytesBuffer)) != -1) {
				digest.update(bytesBuffer, 0, bytesRead);
			}

			byte[] hashedBytes = digest.digest();
			return convertByteArrayToHexString(hashedBytes);
		} catch (FileNotFoundException e) {
		} catch (NoSuchAlgorithmException | IOException e) {
		}
		return null;
	}

	/**
	 * convertByteArrayToHexString converts byte array to hex string.
	 *
	 * @param arrayBytes byte array of hash digest.
	 * @return returns the string format of digest byte array
	 */
	private static String convertByteArrayToHexString(byte[] arrayBytes) {
		StringBuffer stringBuffer = new StringBuffer();
		for (int i = 0; i < arrayBytes.length; i++) {
			String hex = Integer.toHexString(0xFF & arrayBytes[i]);
			if (hex.length() == 1) {
				stringBuffer.append('0');
			}
			stringBuffer.append(hex);
		}
		return stringBuffer.toString();
	}

	public static void updateShaAndSize(DeployedApplication deployedApplication) {
		File deplyementDirFile = new File(deployedApplication.getDeployedPath());
		if (deplyementDirFile.isFile()) {
			deployedApplication.setSha256(getChecksum(deplyementDirFile));
			deployedApplication.setSize(FileUtils.byteCountToDisplaySize(FileUtils.sizeOf(deplyementDirFile)));
		} else {
			deployedApplication.setSha256(getSHA256ForDirectory(deplyementDirFile.getAbsolutePath()));
			deployedApplication.setSize(FileUtils.byteCountToDisplaySize(FileUtils.sizeOfDirectory(deplyementDirFile)));
		}
	}

	public static String getSHA256ForDirectory(String file) {
		File tmpShaFile = null;
		FileOutputStream fOutputStream = null;
		try {
			tmpShaFile = Files.createTempFile(Paths.get(TMP_DIR), K2_TEMP_DIR, "sha").toFile();
			File dir = new File(file);
			fOutputStream = new FileOutputStream(tmpShaFile);
//			System.out.println("Dir : "+file);
			if (dir.isDirectory()) {

				Collection<File> allFiles = FileUtils.listFiles(dir, TrueFileFilter.INSTANCE, TrueFileFilter.INSTANCE);
				List<File> sortedFiles = new ArrayList<>(allFiles);
				Collections.sort(sortedFiles);
				logger.log(LogLevel.DEBUG, "Sort dir for sha : " + sortedFiles, HashGenerator.class.getName());
//				System.out.println(sortedFiles);
				for (File tempFile : sortedFiles) {
					String extension = FilenameUtils.getExtension(tempFile.getName());
					if (OTHER_CRITICAL_FILE_EXT.contains(extension)
							|| JAVA_APPLICATION_ALLOWED_FILE_EXT.contains(extension)) {
//						System.out.println("file : "+tempFile);
						IOUtils.write(tempFile.getName() + getChecksum(tempFile) + StringUtils.LF,
								fOutputStream, StandardCharsets.UTF_8);
					}
				}
				try {
					fOutputStream.close();
				} catch (IOException e1) {
				}
//				System.out.println(FileUtils.sizeOfAsBigInteger(tmpShaFile));
				return getChecksum(tmpShaFile);
			}

		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				FileUtils.forceDelete(tmpShaFile);
			} catch (IOException e) {
			}
		}
		return null;
	}


	public static String getSHA256HexDigest(List<String> data) {
		data.removeAll(Collections.singletonList(null));
		String input = StringUtils.join(data, TWO_PIPES);
		return getChecksum(input);
	}

	public static void createTarGz(File tmpAppDir, File tmpTarFile) throws IOException {
		BufferedOutputStream bOutputStream = null;
		TarArchiveOutputStream tarArchiveOutputStream = null;
		try {
			bOutputStream = new BufferedOutputStream(new FileOutputStream(tmpTarFile));
			tarArchiveOutputStream = new TarArchiveOutputStream(bOutputStream, StandardCharsets.UTF_8.displayName());
			tarArchiveOutputStream.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX);
			addFilesToTarGZ(tmpAppDir.toString(), StringUtils.EMPTY, tarArchiveOutputStream);
		} finally {
			tarArchiveOutputStream.close();
			bOutputStream.close();
		}
	}

	@Deprecated
	public static void calculateDirShaAndSize(DeployedApplication deployedApplication) {
		File tmpAppDir = null;
		File tmpTarFile = null;
		try {
			tmpAppDir = createTmpDirWithResource(deployedApplication.getDeployedPath());

			tmpTarFile = Files.createTempFile(K2_TEMP_DIR, TAR_GZ).toFile();
			createTarGz(tmpAppDir, tmpTarFile);
			logger.log(LogLevel.DEBUG, TAR_SIZE + FileUtils.sizeOf(tmpTarFile), HashGenerator.class.getName());
			deployedApplication.setSize(FileUtils.byteCountToDisplaySize(FileUtils.sizeOf(tmpTarFile)));
			deployedApplication.setSha256(getChecksum(tmpTarFile));
		} catch (Throwable e) {
			logger.log(LogLevel.ERROR, ERROR2, e, HashGenerator.class.getName());
		} finally {
			try {
				FileUtils.forceDelete(tmpTarFile);
				FileUtils.forceDelete(tmpAppDir);
			} catch (IOException e) {
			}
		}
	}

	private static File createTmpDirWithResource(String deployedPath) throws IOException {
		File tmpShaDir;
		tmpShaDir = Files.createTempDirectory(Paths.get(TMP_DIR), K2_TEMP_DIR).toFile();

		FileUtils.copyDirectory(new File(deployedPath), tmpShaDir);
		System.out.println("Directory is copied.");
		removeNonResource(tmpShaDir);
		System.out.println("Removed unwanted files!");
		return tmpShaDir;
	}

	private static void removeNonResource(File dir) throws IOException {
		if (dir.isDirectory()) {
			Iterator<File> fileIterator = FileUtils.iterateFilesAndDirs(dir, TrueFileFilter.INSTANCE,
					TrueFileFilter.INSTANCE);
			while (fileIterator.hasNext()) {
				File tempFile = fileIterator.next();

				if (tempFile.isFile()) {
					String extension = FilenameUtils.getExtension(tempFile.getName());
					if (!(OTHER_CRITICAL_FILE_EXT.contains(extension)
							|| JAVA_APPLICATION_ALLOWED_FILE_EXT.contains(extension))) {
						logger.log(LogLevel.DEBUG, FILE_FOR_SHA_CALC + tempFile.getAbsolutePath(),
								HashGenerator.class.getName());
						FileUtils.forceDeleteOnExit(tempFile);
					}
				}
			}
		} else if (dir.isFile()) {
			String extension = FilenameUtils.getExtension(dir.getName());
			if (!OTHER_CRITICAL_FILE_EXT.contains(extension)) {
				FileUtils.forceDeleteOnExit(dir);
			} else if (!JAVA_APPLICATION_ALLOWED_FILE_EXT.contains(extension)) {
				FileUtils.forceDeleteOnExit(dir);
			}
		}
	}

	private static void addFilesToTarGZ(String filePath, String parent, TarArchiveOutputStream tarArchive)
			throws IOException {
		File file = new File(filePath);
		// Create entry name relative to parent file path
		String entryName = parent + file.getName();
		// add tar ArchiveEntry
		tarArchive.putArchiveEntry(new TarArchiveEntry(file, entryName));
		if (file.isFile()) {
			System.out.println("File to add: " + file);
			FileInputStream fis = new FileInputStream(file);
			BufferedInputStream bis = new BufferedInputStream(fis);
			// Write file content to archive
			IOUtils.copy(bis, tarArchive);
			tarArchive.closeArchiveEntry();
			bis.close();
		} else if (file.isDirectory()) {
			// no need to copy any content since it is
			// a directory, just close the outputstream
			tarArchive.closeArchiveEntry();
			// for files in the directories

			List<File> files = Arrays.asList(file.listFiles());
			System.out.println("All files : " + files);
			Collections.sort(files);
			for (File f : files) {
				// recursively call the method for all the subdirectories
				addFilesToTarGZ(f.getAbsolutePath(), entryName + File.separator, tarArchive);
			}
		}
	}

}
