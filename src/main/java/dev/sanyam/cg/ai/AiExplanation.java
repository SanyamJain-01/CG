package dev.sanyam.cg.ai;

import dev.sanyam.cg.finding.Finding;
import jakarta.persistence.*;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.springframework.data.domain.Persistable;

/** AI-generated text about one finding, with the model and prompt version that wrote it. May be wrong. */
@Entity
@Table(name = "ai_explanations")
public class AiExplanation implements Persistable<UUID> {

    @Id
    private UUID id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "finding_id", nullable = false, unique = true)
    private Finding finding;

    @Column(nullable = false, columnDefinition = "text")
    private String model;

    @Column(name = "prompt_version", nullable = false, columnDefinition = "text")
    private String promptVersion;

    @Column(nullable = false, columnDefinition = "text")
    private String risk;

    @Column(nullable = false, columnDefinition = "text")
    private String fix;

    @Column(name = "likely_false_positive", nullable = false)
    private boolean likelyFalsePositive;

    @Column(name = "created_at", nullable = false, columnDefinition = "timestamptz")
    private OffsetDateTime createdAt;

    @Transient
    private boolean isNew = true;

    protected AiExplanation() {
        // for JPA
    }

    public AiExplanation(Finding finding, Explainer.Note note, String model, String promptVersion) {
        this.id = UUID.randomUUID();
        this.finding = finding;
        this.model = model;
        this.promptVersion = promptVersion;
        this.risk = note.risk();
        this.fix = note.fix();
        this.likelyFalsePositive = note.likelyFalsePositive();
        this.createdAt = OffsetDateTime.now();
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

    public UUID getFindingId() { return finding.getId(); }  // reads the foreign key without loading the finding
    public String getModel() { return model; }
    public String getPromptVersion() { return promptVersion; }
    public String getRisk() { return risk; }
    public String getFix() { return fix; }
    public boolean isLikelyFalsePositive() { return likelyFalsePositive; }
}
