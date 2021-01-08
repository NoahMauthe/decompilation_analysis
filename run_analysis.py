#!/usr/bin/env python3

import logging
import os
import sys
from datetime import datetime

import argparse

from analysis import analysis_tool, apkanalyzer

LOGGER = logging.getLogger('analysis')


def _parse_args():
    """Parses command line arguments from stdin and supplies help.

    Returns
    -------
    Namespace:
        The arguments parsed from stdin
    """
    parser = argparse.ArgumentParser(description='Analyze a collection of apk files')
    parser.add_argument('path', type=str,
                        help='specifies the common basepath for all apks')
    parser.add_argument('--logs', dest='log_path', type=str, default=os.getenv('HOME'),
                        required=False, help='specifies the log path')
    parser.add_argument('--verbose', dest='VERBOSE', default=False, required=False, action='store_true',
                        help='enables verbose logging')
    parser.add_argument('--preserve', dest='preserve', default=False, required=False, action='store_true',
                        help='prevents the removal of decompiled sources')
    parser.add_argument('--dex-only', dest='dex', default=False, required=False, action='store_true',
                        help='runs only decompilers that work directly on dex bytecode')
    parser.add_argument('--config', dest='config', required=True, type=str,
                        help='directory containing config files')
    parser.add_argument('--out', dest='out', required=True, type=str,
                        help='path of the output directory')
    return parser.parse_args()


def _setup_logging():
    """Sets up the logger and parses arguments from stdin.

    Returns
    -------
    str :
        The common basepath of all apks.
    bool :
        If set, does not remove decompiled sources.
    str :
        Path to the config directory.
    str :
        Output path.
    bool :
        If set, only dex compatible decompilers will be run
    """
    args = _parse_args()
    if args.VERBOSE:
        LOGGER.setLevel(logging.DEBUG)
    else:
        LOGGER.setLevel(logging.INFO)
    log_path = os.path.abspath(args.log_path)
    os.makedirs(log_path, exist_ok=True)
    file_handler = logging.FileHandler(os.path.join(log_path, f'{datetime.now()}.log'), 'w+')
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(logging.INFO)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(fmt='{asctime} - {name} - {levelname}\n\t{message}', style='{')
    file_handler.setFormatter(formatter)
    stdout_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(stdout_handler)
    return args.path, args.preserve, args.config, args.out, args.dex


if __name__ == '__main__':
    path, preserve, processed, out, dex = _setup_logging()
    apkanalyzer.init_logging(LOGGER)
    analysis_tool.analyse(os.path.abspath(out), os.path.abspath(path), preserve, processed, dex)
