package dev.sanyam.cg.archive;

/** Hard limits for one archive. Anything above them is rejected before or during extraction. */
public record ArchiveLimits(int maxEntries, long maxTotalBytes, long maxFileBytes, long maxRatio) {

    public static final ArchiveLimits DEFAULT =
            new ArchiveLimits(5_000, 100L * 1024 * 1024, 5L * 1024 * 1024, 100);
}
