# ---- build: compile and package the app (tests run in CI, not here) ----
FROM eclipse-temurin:24-jdk AS build
WORKDIR /src
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN ./mvnw -q -B dependency:go-offline          # cached layer: re-downloads only when pom.xml changes
COPY src src
RUN ./mvnw -q -B -DskipTests package && cp target/cg-*.jar /app.jar

# ---- run: JRE + the three scanners, no build tools ----
FROM eclipse-temurin:24-jre
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
# each Python scanner gets its own virtualenv, so their dependencies can never clash; versions are pinned
RUN python3 -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.185.0 \
 && python3 -m venv /opt/bandit && /opt/bandit/bin/pip install --no-cache-dir bandit==1.9.4 \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
 && ln -s /opt/bandit/bin/bandit /usr/local/bin/bandit
# the download is checked against the checksum Gitleaks publishes, so a tampered file fails the build
RUN curl -sSL -o /tmp/gitleaks.tar.gz https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
 && echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  /tmp/gitleaks.tar.gz" | sha256sum -c - \
 && tar xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && rm /tmp/gitleaks.tar.gz \
 && semgrep --version && bandit --version && gitleaks version   # fail the build if any scanner is broken

# uploaded code is untrusted: the app and its scanners never run as root
RUN useradd --create-home --uid 10001 cg
USER cg
WORKDIR /home/cg
COPY --from=build /app.jar /app/app.jar
ENV SPRING_PROFILES_ACTIVE=prod
EXPOSE 8080
# heap capped at half the container's memory, leaving room for Semgrep; Serial GC suits one small CPU
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=50", "-XX:+UseSerialGC", "-Xss512k", "-jar", "/app/app.jar"]
