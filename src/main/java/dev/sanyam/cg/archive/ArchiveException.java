package dev.sanyam.cg.archive;

/** An upload was rejected. The code is stable and shown to users; the message explains it in plain words. */
public class ArchiveException extends RuntimeException {

    private final String code;

    public ArchiveException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
