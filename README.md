# Smart Secure Spring Boot REST API + AI Security Agent Template

A hardened **Spring Boot 4.1.2 (Java 25 LTS)** starter template combining **Spring Security + OAuth2 Resource Server (JWT)**, **Bean Validation**, **Spring Data JPA (PostgreSQL)**, **Spring Boot Actuator**, and a **Spring AI Security Agent** (powered by Ollama or OpenAI) for real-time payload inspection and security audit analysis.

## Why This Configuration?

| Component | Starter / Artifact | Security Role |
| :--- | :--- | :--- |
| **Spring Web** | `spring-boot-starter-web` | Explicit `@RestController` endpoints with DTO boundaries (**Rest Repositories / Spring Data REST is intentionally excluded** to prevent accidental mass-assignment and repository exposure). |
| **Validation** | `spring-boot-starter-validation` | Enforces `@Valid` constraints (`@NotBlank`, `@Size`, `@Pattern`) on incoming request DTOs before business logic or AI evaluation. |
| **Spring Security + OAuth2 Resource Server** | `spring-boot-starter-security` + `spring-boot-starter-oauth2-resource-server` | Stateless bearer JWT authentication (`NimbusJwtDecoder` / `NimbusJwtEncoder`), BCrypt password hashing, and `@PreAuthorize` role-based access control. |
| **Spring Data JPA + PostgreSQL** | `spring-boot-starter-data-jpa` + `postgresql` | Internal `@Repository` interfaces (`UserRepository`, `SecurityAuditLogRepository`, `RefreshTokenRepository`) with `open-in-view: false`. |
| **Spring Boot Actuator** | `spring-boot-starter-actuator` | Exposes `/actuator/health`, `/actuator/metrics`, `/actuator/auditevents`, and `/actuator/httpexchanges` restricted to `ADMIN` and `SECURITY_ANALYST` roles. |
| **Spring AI Model Starter** | `spring-ai-starter-model-ollama` (or `openai`) | Powers `AiSecurityAgentService` and `@Tool`-annotated `SecurityTools` for automated threat scoring (SQLi, XSS, SSRF, BOLA, Prompt Injection) and audit log correlation. |

## Quickstart

### 1. Start PostgreSQL (with `pgvector`) and Ollama
```bash
docker compose up -d
docker exec -it smart-secure-ollama ollama pull llama3.2
```

### 2. Run the Application
```bash
./mvnw spring-boot:run
```

### 3. Key Endpoints
* `POST /api/v1/auth/login` — Authenticate with `@Valid` credentials and receive a signed JWT.
* `POST /api/v1/security/inspect` — Inspect a request payload using the Spring AI Security Agent and log the risk assessment (`ROLE_ADMIN` or `ROLE_SECURITY_ANALYST`).
* `GET /api/v1/security/audit-logs` — Query high-risk security events persisted in PostgreSQL (`ROLE_ADMIN` or `ROLE_SECURITY_ANALYST`).
