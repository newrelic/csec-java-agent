package com.newrelic.agent.security.instrumentator.utils;

import com.newrelic.agent.security.intcodeagent.filelogging.FileLoggerThreadPool;
import com.newrelic.api.agent.security.utils.logging.LogLevel;
import com.newrelic.agent.security.intcodeagent.logging.DeployedApplication;
import net.openhft.hashing.LongHashFunction;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class HashGenerator {

    private static final String TMP_DIR = "/tmp/";
    private static final String ERROR2 = "Error : ";
    private static final String TAR_SIZE = "tar size : ";
    private static final String TAR_GZ = "tar.gz";
    private static final String K2_TEMP_DIR = "NR-CSEC-";
    private static final Set<String> JAVA_APPLICATION_ALLOWED_FILE_EXT = new HashSet<>(
            Arrays.asList(new String[]{"java", "jsp", "class", "jar", "war", "ear"}));
    private static final Set<String> OTHER_CRITICAL_FILE_EXT = new HashSet<>(
            Arrays.asList(new String[]{"htm", "html", "js"}));
    private static final String TWO_PIPES = "||";

    private static final FileLoggerThreadPool logger = FileLoggerThreadPool.getInstance();
    public static final String SHA_256 = "SHA-256";
    public static final String FILE_FOR_SHA_CALC = "File for SHA calc : ";
    public static final String UNSORTED_SHA_LIST = "Unsorted SHA list : ";
    public static final String SORTED_SHA_LIST = "Sorted SHA list : ";
    public static final String ERROR = "Error :";
    public static final String WEBAPP_DETECTION_SHA_INFO_S = "Webapp detection SHA info :  %s";
    public static final String STRING_SEP = "-";
    private static final LongHashFunction xxHashFunction = LongHashFunction.xx3(3214658854114272368L);

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
            logger.log(LogLevel.SEVERE, ERROR, e, HashGenerator.class.getName());
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

            byte[] bytesBuffer = new byte[102400];
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
        if (StringUtils.isBlank(deployedApplication.getDeployedPath())) {
            logger.log(LogLevel.WARNING, "Empty deployed path detected. Not calculating SHA256 & size.", HashGenerator.class.getName());
            return;
        }
        if (deplyementDirFile.isFile()) {
            deployedApplication.setSha256(getChecksum(deplyementDirFile));
            deployedApplication.setSize(FileUtils.byteCountToDisplaySize(FileUtils.sizeOf(deplyementDirFile)));
        } else {
            deployedApplication.setSha256(getSHA256ForDirectory(deplyementDirFile.getAbsolutePath()));
            deployedApplication.setSize(FileUtils.byteCountToDisplaySize(FileUtils.sizeOfDirectory(deplyementDirFile)));
        }
    }

    public static String getSHA256ForDirectory(String file) {
        try {
            File dir = new File(file);
            if (dir.isDirectory()) {
                List<String> sha256s = new ArrayList<>();
                Collection<File> allFiles = FileUtils.listFiles(dir, TrueFileFilter.INSTANCE, TrueFileFilter.INSTANCE);
                List<File> sortedFiles = new ArrayList<>(allFiles);
                Collections.sort(sortedFiles);
                for (File tempFile : sortedFiles) {
                    String extension = FilenameUtils.getExtension(tempFile.getName());
                    if (OTHER_CRITICAL_FILE_EXT.contains(extension)
                            || JAVA_APPLICATION_ALLOWED_FILE_EXT.contains(extension)) {
                        sha256s.add(getChecksum(tempFile));
                    }
                }
                return getSHA256HexDigest(sha256s);
            }
        } catch (Exception e) {
            logger.log(LogLevel.SEVERE, ERROR, e, HashGenerator.class.getName());
        }
        return null;
    }

    public static String getSHA256HexDigest(List<String> data) {
        data.removeAll(Collections.singletonList(null));
        String input = StringUtils.join(data);
        return getChecksum(input);
    }
    public static String getSHA256HexDigest(String data) {
        String input = StringUtils.join(data);
        return getChecksum(input);
    }
    
    /**
     * Gets the xxHash64 hex digest.
     *
     * @param data list of strings whose hash is to be generated
     * @return the digest as a hex string
     */
    public static String getXxHash64Digest(List<?> data) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream outputStream = new ObjectOutputStream(byteArrayOutputStream);
        outputStream.writeObject(data);
        return String.valueOf(xxHashFunction.hashBytes(byteArrayOutputStream.toByteArray()));
    }

    /**
     * Gets the xxHash64 hex digest.
     *
     * @param data array of Integers whose hash is to be generated
     * @return the digest as a hex string
     */
    public static String getXxHash64Digest(int[] data) throws IOException {
        return String.valueOf(xxHashFunction.hashInts(data));
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
            logger.log(LogLevel.FINER, TAR_SIZE + FileUtils.sizeOf(tmpTarFile), HashGenerator.class.getName());
            deployedApplication.setSize(FileUtils.byteCountToDisplaySize(FileUtils.sizeOf(tmpTarFile)));
            deployedApplication.setSha256(getChecksum(tmpTarFile));
        } catch (Throwable e) {
            logger.log(LogLevel.SEVERE, ERROR2, e, HashGenerator.class.getName());
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
                        logger.log(LogLevel.FINER, FILE_FOR_SHA_CALC + tempFile.getAbsolutePath(),
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
