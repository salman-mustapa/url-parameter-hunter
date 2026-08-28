"""Run with python -m app.lab --output storage/local-lab-report.json."""

import argparse
import asyncio
import json
from pathlib import Path

from app.lab.runtime import local_lab
from app.lab.workflow import investigate_local_lab


async def main(output):
    async with local_lab() as (base, state):
        report = await investigate_local_lab(base, state)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "status": report["status"],
                "report": str(output.resolve()),
                "findings": len(report["findings"]),
            }
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run a disposable synthetic local evidence investigation"
    )
    parser.add_argument("--output", type=Path, default=Path("storage/local-lab-report.json"))
    asyncio.run(main(parser.parse_args().output))
