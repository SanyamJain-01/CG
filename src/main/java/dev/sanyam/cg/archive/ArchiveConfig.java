package dev.sanyam.cg.archive;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** SafeExtractor itself has no Spring code, so it can be tested and reused on its own. */
@Configuration
class ArchiveConfig {

    @Bean
    SafeExtractor safeExtractor() {
        return new SafeExtractor(ArchiveLimits.DEFAULT);
    }
}
