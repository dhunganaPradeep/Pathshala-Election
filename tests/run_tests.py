import os
import subprocess
import sys
import argparse
import logging
import platform
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def install_dependencies():
    logging.info("Installing dependencies...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        logging.info("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error installing dependencies: {str(e)}")
        return False

def extract_codes():
    if not os.path.exists("extract_voting_codes.py"):
        logging.error("extract_voting_codes.py not found!")
        return False
    
    logging.info("Extracting voting codes from PDF...")
    try:
        subprocess.run([sys.executable, "extract_voting_codes.py"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Error extracting codes: {str(e)}")
        return False

def run_tests(verbose=False, specific_test=None, num_voters=None):
    logging.info("Running tests...")
    cmd = [sys.executable, "-m", "pytest"]
    
    if specific_test:
        cmd.append(f"test_concurrent_voting.py::TestConcurrentVoting::{specific_test}")
    else:
        cmd.append("test_concurrent_voting.py")
    if verbose:
        cmd.extend(["-vv"])
    
    if platform.system() == "Windows":
        cmd.append("--no-header")  # Reduce output clutter
        cmd.append("--no-summary")  # Reduce output clutter
    
    env = os.environ.copy()
    if num_voters:
        env["TEST_NUM_VOTERS"] = str(num_voters)
        logging.info(f"Testing with {num_voters} concurrent voters")
    
    try:
        result = subprocess.run(cmd, capture_output=verbose, env=env)
        if result.returncode == 0:
            logging.info("Tests completed successfully")
            return True
        else:
            if verbose:
                logging.error("Tests failed")
                if result.stdout:
                    print("\nTest output:")
                    print(result.stdout.decode('utf-8'))
                if result.stderr:
                    print("\nTest errors:")
                    print(result.stderr.decode('utf-8'))
            else:
                logging.error(f"Tests failed with error code {result.returncode}")
            return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Tests failed with error code {e.returncode}")
        return False
    except Exception as e:
        logging.error(f"Error running tests: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Run concurrent voting tests")
    parser.add_argument("--skip-deps", action="store_true", help="Skip dependency installation")
    parser.add_argument("--skip-extract", action="store_true", help="Skip code extraction")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--test", help="Run a specific test (e.g., test_multiple_concurrent_voters)")
    parser.add_argument("--voters", type=int, help="Number of concurrent voters to test (default: 10)")
    
    args = parser.parse_args()
    
    if not args.skip_deps:
        if not install_dependencies():
            return 1
    
    if not args.skip_extract:
        extract_codes()
    
    if platform.system() == "Windows":
        time.sleep(1)
    
    if not run_tests(args.verbose, args.test, args.voters):
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 