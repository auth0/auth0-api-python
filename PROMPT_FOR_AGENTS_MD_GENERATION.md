# Generate AGENTS.MD for Any Repository

> **Purpose**: Use this prompt in any repository to generate a comprehensive AGENTS.MD file that enables AI coding assistants to autonomously understand and modify the codebase.

---

## Instructions for AI Agent

I need you to create a comprehensive **AGENTS.MD** file for this SDK repository. This file should enable AI coding assistants (like yourself) to help **customers integrate and use this SDK** in their applications. When customers say "add Auth0 authentication to my API" or "protect my endpoints with this SDK", the AI should generate complete, production-ready integration code.

### Reference Example

First, please read the following AGENTS.MD file as a reference example for tone, structure, and comprehensiveness:

**File to read**: `EXAMPLE_AGENTS.md`

This reference file demonstrates:
- **Comprehensive coverage**: Every aspect of the repository is documented
- **Practical examples**: Real code snippets showing how to implement features
- **Step-by-step guides**: Detailed instructions for common modifications
- **AI-agent friendly**: Written specifically for LLM consumption, not just humans
- **Action-oriented**: Focuses on "how to do X" rather than just "what X is"

### Your Task

Analyze THIS SDK repository and create an AGENTS.MD file that helps customers **USE** the SDK in their applications (not modify the SDK itself). Follow the same structure, tone, and level of detail as the reference example.

**CRITICAL**: This is NOT about SDK development or modifying SDK source code. This is about helping customers integrate the SDK into THEIR applications.

### Structure to Follow

Your AGENTS.MD should include these sections (adapt as needed for this repository's tech stack):

1. **SDK Overview**
   - **Installation instructions** (adapt to language: npm/yarn for JS, pip/poetry for Python, Maven/Gradle for Java, Swift Package Manager/CocoaPods for iOS, etc.)
   - Link to README for detailed installation and prerequisites
   - What this SDK does (purpose, key features)
   - Technology stack and key characteristics
   - Typical customer use cases

2. **Quick Start for AI Agents**
   - Typical workflow when customer requests SDK integration
   - Step-by-step: Understand setup → Locate code → **Install SDK** → Implement integration → Add tests
   - How to integrate this SDK into customer's application
   - Where customers integrate the SDK (adapt to SDK type: routes, components, app initialization, etc.)
   - How to implement the SDK's main functionality in customer's code
   - How to handle errors in customer's application
   - Example: "Customer says: Add [SDK functionality] to my app" → Complete implementation (including installation)

3. **Integration Patterns** (Adapt to SDK Type)
   
   **For Backend/API SDKs** (e.g., auth0-api-python, auth0-api-node):
   - Primary framework patterns (e.g., FastAPI, Flask, Django for Python; Express, Fastify for Node)
   - Integration approach for each (middleware, decorators, route guards, etc.)
   - Complete working examples for 2-3 main frameworks
   
   **For Frontend SDKs** (e.g., auth0-react, auth0-vue):
   - Primary framework patterns (e.g., React hooks, Vue composables, Angular services)
   - Component integration examples
   - State management patterns
   - Routing protection patterns
   
   **For Mobile SDKs** (e.g., Auth0.swift, Auth0.Android):
   - Platform-specific integration (SwiftUI, UIKit, Jetpack Compose, XML layouts)
   - Lifecycle handling
   - Secure storage patterns
   
   **For Server/Full-Stack SDKs** (e.g., nextjs-auth0):
   - Server-side and client-side integration
   - Session management patterns
   - API route protection
   
   **If SDK integrates with other SDKs** (e.g., API SDK + Frontend SDK):
   - Integration guidelines section (open-ended, flexible)
   - Flow diagrams showing complete architecture
   - Configuration matching requirements (e.g., audience, domain)
   - Common integration issues and solutions

4. **SDK Configuration Guide**
   - How customers configure the SDK for their use case
   - All configuration options and what they control
   - SDK-specific modes/features (e.g., Bearer vs DPoP for API SDKs, session vs token for web SDKs)
   - Multi-tenant/multi-environment patterns (if applicable)
   - Environment-specific configurations (dev, staging, production)

5. **Common Integration Scenarios**
   - 10+ real-world customer use cases with COMPLETE implementations
   - Adapt scenarios to SDK type and common customer needs
   
   **Examples for Backend/API SDKs:**
   - "Protect specific routes/endpoints"
   - "Check for scopes/permissions"
   - "Cache validation for performance"
   - "Multi-tenant support"
   - "WebSocket/realtime authentication"
   - "Background job authentication"
   - "Service-to-service auth"
   
   **Examples for Frontend/Mobile SDKs:**
   - "Protect specific routes/screens"
   - "Handle login/logout flow"
   - "Refresh tokens automatically"
   - "Handle auth state in UI"
   - "Deep linking after authentication"
   - "Custom UI for login"
   - "Silent authentication"
   
   **Examples for Full-Stack SDKs:**
   - "Protect API routes and pages"
   - "Server-side rendering with auth"
   - "Client-side auth state"
   - "Session management"
   
   Each scenario must include: setup, complete code, tests (if applicable), error handling

6. **Error Handling in Customer Applications**
   - Understanding SDK error types customers will encounter
   - How to handle errors in customer's application (adapt to SDK type)
   - Proper error responses (HTTP status codes for APIs, UI messages for frontend, alerts for mobile)
   - Custom error handling matching customer's application patterns
   - Logging errors for debugging and security monitoring
   - Example error handlers for common scenarios

7. **Testing Customer Integrations**
   - How customers test their integration (adapt to SDK type: API tests, UI tests, unit tests)
   - Test fixtures and helpers (e.g., mock tokens, test users, test configs)
   - Mocking the SDK for unit tests
   - Integration testing with real Auth0 (if applicable)
   - Example test suites
   - Testing different scenarios (success, failure, edge cases)

8. **Troubleshooting Guide**
   - Common customer issues and solutions (adapt to SDK type)
   - SDK-specific errors and how to resolve them
   - Configuration issues (domain, client ID, audience, redirects, etc.)
   - Integration issues (CORS, missing dependencies, version conflicts)
   - Auth flow issues (redirects, callbacks, state management)
   - Debugging techniques customers can use
   - How to inspect/verify SDK state (tokens, sessions, configs, etc.)
   - How to test Auth0 configuration

9. **SDK Configuration Reference**
   - Complete reference for all configuration options
   - Configuration recommendations by use case
   - Security best practices
   - Performance best practices
   - Error handling best practices

10. **Best Practices for Customer Integration**
    - Security: HTTPS, secure storage, don't log sensitive data, token/session handling
    - Performance: SDK instance reuse, caching strategies, minimize Auth0 API calls
    - Error handling: User-friendly messages, proper error codes/responses, graceful degradation
    - Testing: Test all scenarios, use test Auth0 tenant/environment
    - Monitoring: Log important events, track metrics (adapt to SDK type)
    - Production readiness: Environment configs, secrets management, deployment considerations

11. **Quick Reference**
    - SDK methods/APIs customers will use (with brief examples)
    - Configuration options quick reference
    - Error types customers will encounter
    - Key concepts quick reference (adapt to SDK: claims, session data, auth state, etc.)
    - Tables for easy lookup

12. **AI Agent Checklist for Customer Integrations**
    - Configuration checklist (adapt to SDK: domain, client ID, audience, redirects, etc.)
    - Code integration checklist (SDK setup, integration points, error handling)
    - Testing checklist (success cases, failure cases, edge cases)
    - Security checklist (HTTPS, secure storage, no sensitive data in logs, proper auth flow)
    - Documentation checklist (how customers use it, example code, troubleshooting)

13. **Resources for Customers**
    - Auth0 Documentation links
    - SDK GitHub repository and issues
    - Relevant RFC standards (if applicable: JWT, OAuth 2.0, OIDC, DPoP, etc.)
    - Platform/framework-specific documentation
    - Community resources (forums, Stack Overflow tags, etc.)
    - Testing and development tools

### Tone and Style Guidelines

Match the reference example's tone:

- ✅ **Direct and action-oriented**: "Do X by modifying Y"
- ✅ **Comprehensive with examples**: Always show code, not just descriptions
- ✅ **Practical and realistic**: Use real scenarios, not toy examples
- ✅ **AI-agent optimized**: Written for LLM consumption
- ✅ **Well-structured**: Use tables, code blocks, and clear headings
- ✅ **Complete**: Don't skip details - assume the AI agent knows nothing about this repo

- ❌ **Avoid**: Vague descriptions without examples
- ❌ **Avoid**: Marketing language or fluff
- ❌ **Avoid**: Incomplete code snippets
- ❌ **Avoid**: Assuming prior knowledge

### Code Examples

Every section should include:
- **Working code examples** (not pseudocode)
- **Complete implementations** (all imports, full function bodies)
- **Real file paths** and line numbers where applicable
- **Before/after comparisons** for modifications
- **Test examples** for each feature

### Critical Requirements

1. **Explore the SDK thoroughly** before writing
   - Read README.md and EXAMPLES.md first (these show how customers USE the SDK)
   - Use `list_dir`, `read_file`, `grep_search` to understand SDK structure
   - Identify main classes/methods customers will use (e.g., `ApiClient`, `verify_request`)
   - Understand SDK capabilities and configuration options
   - Focus on PUBLIC APIs, not internal implementation

2. **Be specific and accurate**
   - Reference actual SDK class names, method names (what customers import)
   - Show how customers USE the SDK in their applications
   - Include actual error types customers will encounter
   - Reference actual configuration options from SDK docs
   - DO NOT show SDK internal code or how to modify SDK source

3. **Make it actionable for customers**
   - Every "how to" section shows complete customer application code
   - Include all necessary imports and SDK setup
   - Show where in CUSTOMER's app files should be created/modified
   - Include complete test examples for customer's tests
   - Focus on customer's app.py, routes.py, auth.py (not SDK source)

4. **Think from a customer's AI agent perspective**
   - What does an AI need to help a customer integrate this SDK?
   - What are the exact steps to add auth to customer's FastAPI/Flask/Django app?
   - How should customer handle auth errors in their app?
   - How should customer test their protected endpoints?
   - What configuration options does customer need?

### Token Limit Handling - CRITICAL

**You WILL hit token limits when writing comprehensive documentation. Follow these rules:**

1. **Do NOT create shortened or summarized versions** to fit in one file
2. **When you hit the 8192 token limit per tool call**, STOP immediately at that point
3. **Create multiple part files**: `AGENTS_PART1.md`, `AGENTS_PART2.md`, `AGENTS_PART3.md`, etc.
4. **Each part should be logically complete**: End at a section boundary, not mid-sentence
5. **Number parts sequentially**: Start with Part 1, continue with Part 2, 3, 4, 5, and so on
6. **Create as many parts as needed**: Don't restrict yourself to a fixed number of parts
7. **Let me know** when you create each part so I can track progress
8. **Continue in the next part** from exactly where you left off

#### How to Split Dynamically

**The number of parts will vary based on the repository size and complexity.**

Split at major section boundaries when you approach the token limit:
- End each part at the completion of a major section (e.g., end of Section 3, Section 5, etc.)
- Start the next part with the next major section
- If a single section is too large, you may split within that section at logical subsection boundaries
- Always include a clear indicator at the end: "**Continued in AGENTS_PART{N+1}.md**"

**Example for small repository** (3 parts):
- Part 1: Sections 1-5
- Part 2: Sections 6-11
- Part 3: Sections 12-16

**Example for large repository** (7+ parts):
- Part 1: Sections 1-3
- Part 2: Section 4
- Part 3: Sections 5-6
- Part 4: Sections 7-9
- Part 5: Section 10 (if it has many scenarios)
- Part 6: Sections 11-13
- Part 7: Sections 14-16

**The key principle**: Comprehensive detail over brevity. Create as many parts as needed.

### Expected Output

After completion, customers should be able to:
1. Tell AI: **"Add Auth0 authentication to my FastAPI API"** → AI integrates SDK completely
2. Tell AI: **"Protect my /api/users endpoint with DPoP"** → AI implements DPoP auth
3. Tell AI: **"Add scope checking for admin routes"** → AI adds scope validation
4. Tell AI: **"Why am I getting audience mismatch?"** → AI debugs using troubleshooting guide
5. Tell AI: **"Add tests for my protected endpoints"** → AI creates proper test suite

The AGENTS.MD should be so comprehensive that an AI agent with NO prior knowledge of this SDK can help customers integrate it into their applications with production-ready code.

### Delivery Format

- Create `AGENTS_PART1.md`, `AGENTS_PART2.md`, etc. as needed
- Each part should be self-contained with proper markdown formatting
- Use code fences with language tags for all code blocks
- Use tables for reference information
- Include a table of contents in Part 1

### Start Now

Begin by:
1. **Read README.md and EXAMPLES.md** - Understand how customers use this SDK (including installation)
2. **Explore public API** - Identify classes/methods customers import
3. **Check configuration options** - What can customers configure?
4. **Review error types** - What errors will customers encounter?
5. **Then start writing AGENTS_PART1.md** with:
   - Section 1: Installation instructions + SDK overview
   - Section 2: Quick start with complete example (including pip install step)

**CRITICAL REMINDERS**:
- This is for SDK **USERS** (customers), not SDK **DEVELOPERS**
- Show how to integrate SDK into customer apps (FastAPI/Flask/Django)
- Focus on customer's app.py, routes.py, auth.py (not SDK internal files)
- Examples should be customer application code using the SDK
- Comprehensive and detailed > brief and incomplete. Create as many parts as needed.

---
