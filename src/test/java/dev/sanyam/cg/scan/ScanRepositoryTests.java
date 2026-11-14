package dev.sanyam.cg.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.sanyam.cg.TestcontainersConfiguration;
import dev.sanyam.cg.user.User;
import dev.sanyam.cg.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Transactional  // each test is rolled back, so tests don't affect each other
class ScanRepositoryTests {

    @Autowired UserRepository users;
    @Autowired ScanRepository scans;

    @Test
    void usersOnlySeeTheirOwnScans() {
        User alice = users.save(new User("alice@example.com", "hash"));
        User bob = users.save(new User("bob@example.com", "hash"));
        Scan scan = scans.save(new Scan(alice, "repo.zip"));

        assertThat(scans.findTop20ByUser_IdOrderByCreatedAtDesc(alice.getId())).containsExactly(scan);
        assertThat(scans.findTop20ByUser_IdOrderByCreatedAtDesc(bob.getId())).isEmpty();
        assertThat(scans.findByIdAndUser_Id(scan.getId(), bob.getId())).isEmpty();
    }

    @Test
    void emailIsUniqueIgnoringCase() {
        users.saveAndFlush(new User("Alice@Example.com", "hash"));

        assertThatThrownBy(() -> users.saveAndFlush(new User("alice@example.com", "hash")))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void databaseRejectsAFourthAttempt() {
        Scan scan = new Scan(users.save(new User("carol@example.com", "hash")), "repo.zip");
        for (int i = 0; i < 4; i++) {
            scan.startAttempt();
        }

        assertThatThrownBy(() -> scans.saveAndFlush(scan))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}
