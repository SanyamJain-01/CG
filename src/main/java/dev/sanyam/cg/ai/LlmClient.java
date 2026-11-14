package dev.sanyam.cg.ai;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import tools.jackson.databind.ObjectMapper;

/**
 * Talks to any OpenAI-compatible chat API (Groq by default, or a local Ollama). Without an API key it reports
 * itself as not configured and is never called, so CG works fully without an LLM.
 */
@Component
public class LlmClient {

    static final Duration TIMEOUT = Duration.ofSeconds(60);

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ChatResponse(List<Choice> choices) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Choice(Message message) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Message(String content) {
    }

    private final ObjectMapper json;
    private final RestClient http;
    private final String apiKey;
    private final String model;

    public LlmClient(ObjectMapper json,
                     @Value("${cg.llm.base-url:https://api.groq.com/openai/v1}") String baseUrl,
                     @Value("${cg.llm.api-key:}") String apiKey,
                     @Value("${cg.llm.model:openai/gpt-oss-120b}") String model) {
        this.json = json;
        this.apiKey = apiKey.strip();
        this.model = model;
        JdkClientHttpRequestFactory requests = new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
        requests.setReadTimeout(TIMEOUT);
        this.http = RestClient.builder().baseUrl(baseUrl).requestFactory(requests).build();
    }

    public boolean isConfigured() {
        return !apiKey.isEmpty();
    }

    public String model() {
        return model;
    }

    /** Sends the conversation and returns the model's reply text. Errors never include the key or the prompt. */
    public String complete(List<Map<String, String>> messages) {
        String body = json.writeValueAsString(Map.of(
                "model", model,
                "temperature", 0,                                  // same input, same answer, as far as possible
                "response_format", Map.of("type", "json_object"),  // ask for JSON; it is still validated
                "messages", messages));
        String raw;
        try {
            raw = http.post().uri("/chat/completions")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + apiKey)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .body(String.class);
        } catch (RestClientResponseException e) {
            throw new LlmException("HTTP " + e.getStatusCode().value());
        } catch (ResourceAccessException e) {
            throw new LlmException("unreachable or timed out");
        }
        try {
            ChatResponse response = json.readValue(raw, ChatResponse.class);
            return response.choices().getFirst().message().content();
        } catch (RuntimeException e) {  // Jackson 3 errors are unchecked; so is a missing field
            throw new LlmException("unexpected response shape");
        }
    }
}
