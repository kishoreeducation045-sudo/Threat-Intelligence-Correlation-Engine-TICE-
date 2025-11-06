import asyncio
from functools import wraps
from ..config import MAX_RETRIES


def with_retries(retries: int = None, delay_seconds: float = 0.5):
    count = MAX_RETRIES if retries is None else retries

    def deco(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(count + 1):
                try:
                    return await fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    if attempt < count:
                        await asyncio.sleep(delay_seconds)
            raise last_exc

        return wrapper

    return deco


