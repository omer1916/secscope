# Adding a scan module

A new scanner is **one file + one registry line**.

1. Create `src/secscope/modules/<name>.py`:

```python
from typing import ClassVar

from secscope.core.models import Category, LocalizedStr
from secscope.modules.base import BaseModule, Emitter, ModuleResult, Requirements, ScanContext


class HeadersModule(BaseModule):
    id: ClassVar[str] = "headers"
    title: ClassVar[LocalizedStr] = LocalizedStr(tr="Güvenlik başlıkları", en="Security headers")
    category: ClassVar[Category] = Category.SECURITY
    requires: ClassVar[Requirements] = Requirements(target_running=True)
    depends_on: ClassVar[tuple[str, ...]] = ()   # e.g. ("intake",)
    exclusive: ClassVar[bool] = False             # True for load tests / ZAP
    timeout_s: ClassVar[float] = 300

    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult:
        async with ctx.http_client() as client:     # the ONLY way to reach the network
            response = await client.get(ctx.target_url)
            await ctx.checkpoint()                    # honours pause/cancel
            ...
            emit.finding(...)                         # findings stream to the UI immediately
        return ModuleResult(data={"urls": [...]})     # visible to dependants via ctx.results
```

2. Register it in `src/secscope/modules/registry.py`:

```python
BUILTIN_MODULES = (..., "secscope.modules.headers:HeadersModule")
```

## Rules

- Network: only `ctx.http_client()` or `ctx.guard.open_connection()`. Importing `socket`,
  `httpx.Client`, `urllib.request`… fails lint and `tests/unit/test_network_ban.py`.
- External tools: list them in `requires.tools`; the base `preflight` turns a missing or
  too-old tool into `SKIPPED` with the manifest's install hint. Start processes with
  `ManagedProcess` (`async with`), never `subprocess.Popen`, so cancel kills the whole tree.
- Call `await ctx.checkpoint()` inside long loops.
- Every `rule_id` you emit needs `remediation/<rule_id>.yaml`, a positive and a negative
  fixture, and references (CWE/OWASP).
- Secrets in evidence are masked automatically by the models; target-supplied text is
  HTML-escaped by the report layer — never build HTML yourself.
