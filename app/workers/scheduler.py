import asyncio, logging
logger = logging.getLogger("worker")
async def main():
    logger.info("Worker scheduler started")
    while True:
        await asyncio.sleep(60)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
