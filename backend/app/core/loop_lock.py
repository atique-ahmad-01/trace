"""asyncio locks scoped per event loop.

Background jobs run on separate threads, each with its own event loop, so a
module-level asyncio.Lock cannot be shared between them.
"""

import asyncio
import weakref


class LoopLock:
    def __init__(self):
        self._locks: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock]" = weakref.WeakKeyDictionary()

    def get(self) -> asyncio.Lock:
        loop = asyncio.get_running_loop()
        lock = self._locks.get(loop)
        if lock is None:
            lock = self._locks[loop] = asyncio.Lock()
        return lock

    async def __aenter__(self):
        await self.get().acquire()
        return self

    async def __aexit__(self, *exc):
        self.get().release()
