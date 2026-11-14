package dev.sanyam.cg.finding;

import dev.sanyam.cg.analysis.Evidence;
import dev.sanyam.cg.scan.Scan;
import jakarta.persistence.*;
import java.util.UUID;
import org.springframework.data.domain.Persistable;

/** A scanner result as stored. Nothing here is AI-generated; explanations live in their own table. */
@Entity
@Table(name = "findings")
public class Finding implements Persistable<UUID> {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "scan_id", nullable = false)
    private Scan scan;

    @Column(nullable = false, columnDefinition = "text")
    private String tool;

    @Column(name = "rule_id", nullable = false, columnDefinition = "text")
    private String ruleId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, columnDefinition = "text")
    private Severity severity;

    @Column(name = "file_path", nullable = false, columnDefinition = "text")
    private String filePath;

    @Column(name = "start_line", nullable = false)
    private int startLine;

    @Column(name = "end_line", nullable = false)
    private int endLine;

    @Column(nullable = false, columnDefinition = "text")
    private String message;

    @Column(nullable = false, columnDefinition = "text")
    private String snippet;

    @Column(nullable = false, columnDefinition = "text")
    private String fingerprint;

    /** Lets saveAll() insert directly instead of selecting first to check whether each row exists. */
    @Transient
    private boolean isNew = true;

    protected Finding() {
        // for JPA
    }

    public Finding(Scan scan, Evidence.Draft draft) {
        this.id = UUID.randomUUID();
        this.scan = scan;
        this.tool = draft.raw().tool();
        this.ruleId = draft.raw().ruleId();
        this.severity = draft.raw().severity();
        this.filePath = draft.raw().file();
        this.startLine = draft.raw().startLine();
        this.endLine = draft.raw().endLine();
        this.message = draft.raw().message();
        this.snippet = draft.snippet();
        this.fingerprint = draft.fingerprint();
    }

    @PostLoad
    @PostPersist
    void markNotNew() {
        isNew = false;
    }

    @Override
    public boolean isNew() { return isNew; }

    @Override
    public UUID getId() { return id; }

    public String getTool() { return tool; }
    public String getRuleId() { return ruleId; }
    public Severity getSeverity() { return severity; }
    public String getFilePath() { return filePath; }
    public int getStartLine() { return startLine; }
    public int getEndLine() { return endLine; }
    public String getMessage() { return message; }
    public String getSnippet() { return snippet; }
    public String getFingerprint() { return fingerprint; }
}
