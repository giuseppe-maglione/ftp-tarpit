import os
import sys
import time
import argparse
import importlib

from src.InjectionManager.default import DefaultInjectionManager
from src.utils import get_local_ip, get_public_ip
from src.utils.logger import logger

def main(args):
    module_name = f"config.{args.conf}"
    
    try:
        conf = importlib.import_module(module_name)
    except ModuleNotFoundError:
        logger.error(f"Configuration file '{args.conf}.py' not found in the 'config' directory.")
        sys.exit(1)
	
    local_ip = get_local_ip()
    public_ip = get_public_ip()

    inj_manager = DefaultInjectionManager(
        conf.TRIGGER_EVENTS,
        local_ip,
        public_ip,
    )
	
    inj_manager.spawn_decoys(conf.DECOYS)

    try:
        print("FTP-Tarpit is running. Press Ctrl-C to exit.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt caught — cleaning up")
        inj_manager.cleanup()
        os._exit(0)
	

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Run FTP-Tarpit on the host machine based on the configuration file provided')

    parser.add_argument('--conf', type=str, default='ftp_tarpit',
                        help='Name of the configuration file inside the config folder (e.g., ftp_tarpit)')
	
    args = parser.parse_args()
    main(args)