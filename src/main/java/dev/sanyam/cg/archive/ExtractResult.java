package dev.sanyam.cg.archive;

public record ExtractResult(int filesWritten, int filesSkipped, long bytesWritten) {
}
