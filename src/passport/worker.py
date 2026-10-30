"""Worker process entry point: ``uv run python -m passport.worker``."""

import asyncio

from passport.jobs import app


async def main() -> None:
    async with app.open_async():
        await app.run_worker_async()


if __name__ == "__main__":
    asyncio.run(main())
