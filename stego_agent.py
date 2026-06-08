"""
stego_agent.py — Unified launcher for steganography detection

Usage:
  python stego_agent.py file.png              # Single file analysis
  python stego_agent.py --watch ./incoming    # Monitor directory (polling every 5s)
  python stego_agent.py --watch ./incoming --logfile custom.log
"""

import sys
import os
import json
import time
import logging
import argparse
from pathlib import Path
from datetime import datetime, timezone

# Add project root and steg-lab to path
_PROJECT_ROOT = Path(__file__).parent
_STEG_LAB = _PROJECT_ROOT / "steg-lab"
sys.path.insert(0, str(_PROJECT_ROOT))
sys.path.insert(0, str(_STEG_LAB))

from detectors import ImageDetector, AudioDetector, NetworkDetector, VideoDetector

# Setup logging
def setup_logging(logfile: str = "stego_agent.log"):
    """Configure logging to file and console."""
    logger = logging.getLogger("stego_agent")
    logger.setLevel(logging.DEBUG)

    # File handler
    fh = logging.FileHandler(logfile)
    fh.setLevel(logging.DEBUG)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # Formatter
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


logger = setup_logging()

# File type routing
IMAGE_FORMATS = {".png", ".bmp", ".tiff", ".tif", ".pgm", ".jpg", ".jpeg", ".jfif", ".webp"}
AUDIO_FORMATS = {".wav", ".wave"}
VIDEO_FORMATS = {".mp4", ".avi", ".mkv", ".mov", ".webm"}
NETWORK_FORMATS = {".json", ".pcap", ".pcapng"}

# Events log path
EVENTS_LOG = "stego_events.ndjson"


class StegoAgent:
    """Unified steganography detection agent."""

    def __init__(self):
        self.image_detector = ImageDetector()
        self.audio_detector = AudioDetector()
        self.network_detector = NetworkDetector()
        self.video_detector = VideoDetector()
        self.processed_files = set()

    def analyze_file(self, filepath: str) -> dict:
        """
        Analyze a single file and return SharedResult as dict.

        Args:
            filepath: path to file to analyze

        Returns:
            dict serializable to JSON
        """
        if not os.path.exists(filepath):
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "stego_scan",
                "errors": f"File not found: {filepath}",
            }

        ext = os.path.splitext(filepath)[1].lower()
        logger.info(f"Analyzing: {filepath} (format: {ext})")

        try:
            if ext in IMAGE_FORMATS:
                result = self.image_detector.analyze(filepath)
            elif ext in AUDIO_FORMATS:
                result = self.audio_detector.analyze(filepath)
            elif ext in VIDEO_FORMATS:
                result = self.video_detector.analyze(filepath)
            elif ext in NETWORK_FORMATS:
                result = self.network_detector.analyze(filepath)
            else:
                logger.warning(f"Unsupported format: {ext}")
                return {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event_type": "stego_scan",
                    "file_name": os.path.basename(filepath),
                    "file_path": os.path.abspath(filepath),
                    "errors": f"Unsupported format: {ext}",
                }

            return result.to_json_dict()

        except Exception as e:
            logger.error(f"Error analyzing {filepath}: {str(e)}", exc_info=True)
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "stego_scan",
                "file_name": os.path.basename(filepath),
                "file_path": os.path.abspath(filepath),
                "errors": f"Analysis failed: {str(e)}",
            }

    def append_event(self, result_dict: dict):
        """
        Append result to NDJSON events log.

        Args:
            result_dict: dict result from analyze_file
        """
        try:
            ndjson_line = json.dumps(result_dict, ensure_ascii=False)
            with open(EVENTS_LOG, "a", encoding="utf-8") as f:
                f.write(ndjson_line + "\n")
            logger.debug(f"Event logged to {EVENTS_LOG}")
        except Exception as e:
            logger.error(f"Failed to write to {EVENTS_LOG}: {str(e)}")

    def process_file(self, filepath: str):
        """
        Process a single file: analyze and log.

        Args:
            filepath: path to file
        """
        abs_path = os.path.abspath(filepath)
        result = self.analyze_file(abs_path)
        self.append_event(result)

        # Print summary
        verdict = result.get("verdict", "UNKNOWN")
        risk_score = result.get("risk_score", 0)
        color = {"CLEAN": "\033[92m", "SUSPICIOUS": "\033[93m", "DETECTED": "\033[91m"}.get(verdict, "")
        reset = "\033[0m"
        print(f"  Result: {color}{verdict}{reset} (risk_score={risk_score})")

    def watch_directory(self, directory: str, poll_interval: int = 5):
        """
        Monitor directory for new files and process them.

        Args:
            directory: path to directory to monitor
            poll_interval: polling interval in seconds (default 5)
        """
        if not os.path.isdir(directory):
            logger.error(f"Directory does not exist: {directory}")
            return

        logger.info(f"Starting directory monitor: {directory} (poll interval: {poll_interval}s)")
        print(f"\n✓ Monitoring {directory} for new files (Ctrl+C to stop)\n")

        try:
            while True:
                try:
                    # Find all files in directory
                    for root, dirs, files in os.walk(directory):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            abs_path = os.path.abspath(filepath)

                            # Skip if already processed
                            if abs_path in self.processed_files:
                                continue

                            self.processed_files.add(abs_path)
                            logger.info(f"New file detected: {filepath}")
                            self.process_file(filepath)

                except Exception as e:
                    logger.error(f"Error during directory scan: {str(e)}")

                time.sleep(poll_interval)

        except KeyboardInterrupt:
            logger.info("Directory monitoring stopped by user")
            print("\n✓ Stopped monitoring")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Unified steganography detection agent for SIEM"
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="File to analyze (or --watch for directory monitoring)"
    )
    parser.add_argument(
        "--watch",
        type=str,
        help="Monitor directory for new files"
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=5,
        help="Directory polling interval in seconds (default: 5)"
    )
    parser.add_argument(
        "--logfile",
        type=str,
        default="stego_agent.log",
        help="Path to log file (default: stego_agent.log)"
    )

    args = parser.parse_args()

    # Reconfigure logging if custom logfile specified
    if args.logfile != "stego_agent.log":
        global logger
        logger = setup_logging(args.logfile)

    agent = StegoAgent()

    if args.watch:
        # Directory monitoring mode
        agent.watch_directory(args.watch, poll_interval=args.poll_interval)
    elif args.file:
        # Single file analysis mode
        agent.process_file(args.file)
    else:
        # Interactive mode
        print("=== Steganography Detection Agent ===")
        print("Enter file path (or 'q' to quit):\n")
        while True:
            try:
                path = input("File: ").strip().strip('"').strip("'")
                if path.lower() in ("q", "quit", "exit", ""):
                    print("Exiting.")
                    break
                agent.process_file(path)
                print()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting.")
                break
            except Exception as e:
                logger.error(f"Error: {str(e)}")
                print(f"Error: {str(e)}\n")


if __name__ == "__main__":
    main()
