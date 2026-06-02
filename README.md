# plugin-credit-dashboard

Credit and billing dashboard plugin for OpenCode and Claude Code. Tracks usage metrics, manages API credits, and synchronizes state via Firebase.

## Under-the-Hood Architecture

```mermaid
flowchart TD
    %% Event Sources
    subgraph Event_Sources [Token & Usage Events]
        CC_HOOK[Claude Code Request Hooks]
        OC_HOOK[OpenCode Interceptor Hooks]
    end

    %% Core Application
    subgraph Dashboard_Core [Dashboard Core (src/)]
        METRICS_AGG[Metrics Aggregator]
        STATE_MGR[State Manager]
        HTTP_SRV[Express UI Server]
        FIREBASE_CLIENT[Firebase Client]
        
        CC_HOOK -->|Token usage| METRICS_AGG
        OC_HOOK -->|Token usage| METRICS_AGG
        
        METRICS_AGG -->|Batch update| STATE_MGR
        STATE_MGR <-->|Sync state| FIREBASE_CLIENT
        STATE_MGR -->|Injects data| HTTP_SRV
    end

    %% External & UI
    subgraph External_Systems [External & Output]
        FB_DB[(Firebase Realtime DB)]
        BROWSER[User Browser UI]
        
        FIREBASE_CLIENT <-->|Read/Write Quota| FB_DB
        HTTP_SRV -->|Serves React/HTML| BROWSER
    end
```

## Structure

- `src/` - Shared core logic (Firebase sync, metrics aggregation)
- `claude/` - Claude Code specific wrappers (standalone processes)
- `opencode/` - OpenCode specific wrappers (inline IDE plugins)
- `dist/` - Single compiled output supporting both environments

## License

MIT
