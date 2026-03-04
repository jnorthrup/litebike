# OpenCode Env Mappings

**Source:** `/Users/jim/work/opencode/packages/opencode/src/provider/provider.ts`  
**Extracted:** 2026-03-04

---

## Provider API Key Environment Variables

### Anthropic
```typescript
ANTHROPIC_API_KEY
```
- Used by: `@ai-sdk/anthropic`
- Beta headers: `claude-code-20250219,interleaved-thinking-2025-05-14,fine-grained-tool-streaming-2025-05-14`

### OpenAI
```typescript
OPENAI_API_KEY
```
- Used by: `@ai-sdk/openai`
- Responses API for GPT-5+

### Google / Vertex AI
```typescript
GOOGLE_CLOUD_PROJECT
GCP_PROJECT
GCLOUD_PROJECT
GOOGLE_CLOUD_LOCATION
VERTEX_LOCATION
GOOGLE_VERTEX_PROJECT
GOOGLE_VERTEX_LOCATION
GOOGLE_VERTEX_ENDPOINT
```
- Used by: `@ai-sdk/google`, `@ai-sdk/google-vertex`
- Default location: `us-central1` or `global`

### AWS Bedrock
```typescript
AWS_REGION
AWS_PROFILE
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_ROLE_ARN
AWS_WEB_IDENTITY_TOKEN_FILE
AWS_BEARER_TOKEN_BEDROCK
AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
AWS_CONTAINER_CREDENTIALS_FULL_URI
```
- Used by: `@ai-sdk/amazon-bedrock`
- Supports credential provider chain

### Azure
```typescript
AZURE_COGNITIVE_SERVICES_RESOURCE_NAME
AZURE_RESOURCE_NAME
AICORE_SERVICE_KEY
AICORE_DEPLOYMENT_ID
AICORE_RESOURCE_GROUP
```
- Used by: `@ai-sdk/azure`, `@ai-sdk/azure-cognitive-services`
- Supports both responses and chat APIs

### GitLab
```typescript
GITLAB_INSTANCE_URL
GITLAB_HOST
GITLAB_TOKEN
GITLAB_TOKEN_OPENCODE
GITLAB_OAUTH_CLIENT_ID
CI_SERVER_FQDN
CI_PROJECT_DIR
CI_WORKLOAD_REF
```
- Used by: `@gitlab/gitlab-ai-provider`
- Default instance: `https://gitlab.com`

### Cloudflare
```typescript
CLOUDFLARE_ACCOUNT_ID
CLOUDFLARE_API_TOKEN
CLOUDFLARE_API_KEY
CF_AIG_TOKEN
CLOUDFLARE_GATEWAY_ID
```
- Used by: Cloudflare Workers AI, Gateway

### OpenRouter
```typescript
OPENROUTER_API_KEY
```
- Used by: `@openrouter/ai-sdk-provider`

### X.AI (Grok)
```typescript
XAI_API_KEY
```
- Used by: `@ai-sdk/xai`

### Mistral
```typescript
MISTRAL_API_KEY
```
- Used by: `@ai-sdk/mistral`

### Groq
```typescript
GROQ_API_KEY
```
- Used by: `@ai-sdk/groq`

### DeepInfra
```typescript
DEEPINFRA_API_KEY
```
- Used by: `@ai-sdk/deepinfra`

### Cerebras
```typescript
CEREBRAS_API_KEY
```
- Used by: `@ai-sdk/cerebras`

### Cohere
```typescript
COHERE_API_KEY
```
- Used by: `@ai-sdk/cohere`

### Together AI
```typescript
TOGETHER_API_KEY
```
- Used by: `@ai-sdk/togetherai`

### Perplexity
```typescript
PERPLEXITY_API_KEY
```
- Used by: `@ai-sdk/perplexity`

### Vercel
```typescript
VERCEL_API_KEY
```
- Used by: `@ai-sdk/vercel`

### GitHub Copilot
```typescript
GITHUB_TOKEN
```
- Used by: Custom GitHub Copilot provider
- Supports both responses and chat APIs

### Hugging Face
```typescript
HUGGING_FACE_API_KEY
HUGGING_FACE_TOKEN
```
- Used by: Hugging Face Inference Providers

### DeepSeek
```typescript
DEEPSEEK_API_KEY
```
- Console: DeepSeek console

### Moonshot (Kimi)
```typescript
MOONSHOT_API_KEY
KIMI_API_KEY
```
- Console: Moonshot AI console

### MiniMax
```typescript
MINIMAX_API_KEY
```
- Console: MiniMax API Console

### Z.AI
```typescript
Z_API_KEY
ZHIPU_API_KEY
```
- Console: Z.AI API console

### IO.NET
```typescript
IO_NET_API_KEY
```
- Console: IO.NET console

### Baseten
```typescript
BASETEN_API_KEY
```

### Fireworks AI
```typescript
FIREWORKS_API_KEY
```
- Console: Fireworks AI console

### Scaleway
```typescript
SCALEWAY_API_KEY
SCALEWAY_ACCESS_KEY
SCALEWAY_SECRET_KEY
```
- Console: Scaleway Console IAM settings

### OVHcloud
```typescript
OVH_API_KEY
```
- Panel: OVHcloud panel

### SAP BTP
```typescript
SAP_BTP_API_KEY
```
- Cockpit: SAP BTP Cockpit

### Helicone
```typescript
HELICONE_API_KEY
```
- Model Directory: Helicone's Model Directory

### Together AI
```typescript
TOGETHER_API_KEY
```
- Console: Together AI console

### Venice AI
```typescript
VENICE_API_KEY
```
- Console: Venice AI console

### Cerebras
```typescript
CEREBRAS_API_KEY
```
- Console: Cerebras console

### Deep Infra
```typescript
DEEPINFRA_API_KEY
```
- Console: Deep Infra dashboard

### Nebius
```typescript
NEBIUS_API_KEY
```
- Console: Nebius Token Factory console

### 302.AI
```typescript
AI302_API_KEY
```
- Console: 302.AI console

---

## OpenCode Specific Variables

```typescript
OPENCODE_API_KEY
OPENCODE_AUTH_JSON
OPENCODE_AUTO_SHARE
OPENCODE_CLIENT
OPENCODE_CONFIG
OPENCODE_CONFIG_CONTENT
OPENCODE_CONFIG_DIR
OPENCODE_DISABLE_AUTOCOMPACT
OPENCODE_DISABLE_AUTOUPDATE
OPENCODE_DISABLE_CLAUDE_CODE
OPENCODE_DISABLE_CLAUDE_CODE_PROMPT
OPENCODE_DISABLE_CLAUDE_CODE_SKILLS
OPENCODE_DISABLE_DEFAULT_PLUGINS
OPENCODE_DISABLE_FILETIME_CHECK
OPENCODE_DISABLE_LSP_DOWNLOAD
OPENCODE_DISABLE_MODELS_FETCH
OPENCODE_DISABLE_PRUNE
OPENCODE_DISABLE_TERMINAL_TITLE
OPENCODE_ENABLE_EXA
OPENCODE_ENABLE_EXPERIMENTAL_MODELS
OPENCODE_EXPERIMENTAL
OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS
OPENCODE_EXPERIMENTAL_DISABLE_COPY_ON_SELECT
OPENCODE_EXPERIMENTAL_DISABLE_FILEWATCHER
OPENCODE_EXPERIMENTAL_EXA
OPENCODE_EXPERIMENTAL_FILEWATCHER
OPENCODE_EXPERIMENTAL_ICON_DISCOVERY
OPENCODE_EXPERIMENTAL_LSP_TOOL
OPENCODE_EXPERIMENTAL_LSP_TY
OPENCODE_EXPERIMENTAL_MARKDOWN
OPENCODE_EXPERIMENTAL_OUTPUT_TOKEN_MAX
OPENCODE_EXPERIMENTAL_OXFMT
OPENCODE_EXPERIMENTAL_PLAN_MODE
OPENCODE_ENABLE_QUESTION_TOOL
OPENCODE_FAKE_VCS
OPENCODE_GIT_BASH_PATH
OPENCODE_MODEL
OPENCODE_MODELS_URL
OPENCODE_PERMISSION
OPENCODE_PORT
OPENCODE_SERVER_PASSWORD
OPENCODE_SERVER_USERNAME
```

---

## Proxy Variables

```typescript
HTTP_PROXY
HTTPS_PROXY
NO_PROXY
NODE_EXTRA_CA_CERTS
```

---

## Model ID Formats

```typescript
provider/model-id
opencode/kimi-k2
opencode/gpt-5.1-codex
opencode/gpt-5.2-codex
anthropic/claude-sonnet-4-5
openai/gpt-4.1
openrouter/google/gemini-2.5-flash
gitlab/duo-chat-haiku-4-5
```

---

## Base URL Patterns

```typescript
https://opencode.ai/zen/v1/chat/completions
https://opencode.ai/zen/v1/messages
https://opencode.ai/zen/v1/models/gemini-3-flash
https://opencode.ai/zen/v1/models/gemini-3-pro
https://opencode.ai/zen/v1/responses
https://RESOURCE_NAME.openai.azure.com/
https://AZURE_COGNITIVE_SERVICES_RESOURCE_NAME.cognitiveservices.azure.com/
```

---

## Integration with literbike/litebike

These env mappings should be added to:
- `literbike/src/provider_facade_models.rs`
- `literbike/src/env_facade_parity.rs`
- `conductor/tracks/ollama-emulator-copilot-20260304/api-env-lookup-table.md`

---

## Key Insights from OpenCode

1. **Provider SDK Pattern**: Uses `@ai-sdk/*` providers with consistent interface
2. **Env.get() Abstraction**: Custom env getter with fallbacks
3. **Custom Model Loaders**: Per-provider customization (anthropic, openai, github-copilot)
4. **OAuth Support**: Built-in OAuth for providers that support it
5. **Gateway Pattern**: `@ai-sdk/gateway` for unified multi-provider access
6. **Vertex AI Special Handling**: Project/location/endpoint resolution
7. **AWS Credential Chain**: Full credential provider chain support
8. **GitLab Integration**: CI/CD environment variable support
