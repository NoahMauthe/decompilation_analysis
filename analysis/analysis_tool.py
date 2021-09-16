import fnmatch
import glob
import json
import logging
import os
import shutil
import signal
import time
import itertools
from json.decoder import JSONDecodeError
from subprocess import Popen, TimeoutExpired

from API.Exceptions import ConfigurationError
from API.Objects import App

from analysis import filewriter
from analysis.apkanalyzer import run_apk_analyzer, ApkAnalyzerError, standardize_fernflower, standardize_procyon, \
    standardize_cfr, standardize_jadx, dex_for_cfr, dex_for_fernflower, dex_for_jadx, dex_for_procyon
from analysis.method import Method

LOGGER = logging.getLogger('analysis.tool')
LOGGER.setLevel(logging.DEBUG)
TIMEOUT = 300
CONVERT_DEX = {
    'cfr': dex_for_cfr,
    'fernflower': dex_for_fernflower,
    'jadx': dex_for_jadx,
    'procyon': dex_for_procyon,
}
NORMALIZE = {
    'cfr': standardize_cfr,
    'fernflower': standardize_fernflower,
    'jadx': standardize_jadx,
    'procyon': standardize_procyon,
}


class APKError(Exception):
    pass


class Packer(Exception):
    pass


class ConversionError(Exception):
    pass


def parse_apkid(file_path):
    """Parses APKiDs output to determine whether a packer was present.

    Parameters
    ----------
    file_path : str
        The log file to analyze

    Returns
    -------
    str or None:
        The name of the discovered packer or None
    """
    with open(file_path, 'r') as file:
        for line in file:
            if 'packer :' in line:
                LOGGER.info(f'Found a packed application!')
                return line.split('packer :')[1].strip()
    return None


def packer(apk_path, directory):
    """Uses APKiD to detect whether an apk was packed.

    Parameters
    ----------
    apk_path : str
        The application to run the detection on.
    directory : str
        The base directory for logfiles and output

    Returns
    -------
    str or None:
        The name of the packer or None
    """
    out = os.path.join(directory, 'apkid')
    os.makedirs(out, exist_ok=True)
    file_path = os.path.join(out, 'output.log')
    error_path = os.path.join(out, 'error.log')
    apkid_path = 'apkid'
    with open(file_path, 'w+') as file:
        with open(error_path, 'w+') as error_file:
            process = Popen([apkid_path, apk_path], stdout=file, stderr=error_file)
            try:
                process.wait(timeout=TIMEOUT)
            except TimeoutExpired:
                LOGGER.error(f'APKiD timed out for {apk_path.split("/")[-1]}')
    return parse_apkid(file_path)


def dex2jar(apk_path, directory, package):
    """Converts an apk to a jar file for further analysis.

    Parameters
    ----------
    apk_path : str
        The application to convert.
    directory : str
        The base directory for logfiles and output

    Returns
    -------
    str:
        The path of the converted jar file.
    """
    out = os.path.join(directory, 'dex2jar')
    log_dir = os.path.join(out, 'logs')
    files = os.path.join(out, 'files')
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(files, exist_ok=True)
    jar = os.path.join(files, package + '.jar')
    dex2jar_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools', 'dex2jar', 'dex-tools',
                                'build', 'distributions', 'dex-tools-2.1-SNAPSHOT', 'd2j-dex2jar.sh')
    dex2jar_args = [dex2jar_path, '-o', jar, apk_path, '--force']
    with open(os.path.join(log_dir, 'stdout.log'), 'w+') as stdout_file:
        with open(os.path.join(log_dir, 'stderr.log'), 'w+') as stderr_file:
            process = Popen(args=dex2jar_args, stdout=stdout_file, stderr=stderr_file)
            try:
                process.wait(TIMEOUT)
            except TimeoutExpired:
                raise ConversionError(f'{package} conversion to jar timed out after {TIMEOUT}')
    if process.returncode != 0:
        raise ConversionError(f'{package} conversion return with nonzero exit code {process.returncode}')
    elif not os.path.exists(jar):
        raise ConversionError(f'{package} conversion was unsuccessful')
    LOGGER.info(f'Created {jar}')
    return jar


def run_decompiler(args, file_path, log_dir, tool, wd=None):
    """Runs a java based decompiler with the given args.

    A convenience method, as all of the decompilers share a common structure.

    Parameters
    ----------
    args : list
        The arguments passed to the decompiler.
    file_path : str
        The path of the application to be decompiled.
        Only used for logging.
    log_dir : str
        The directory to store the log files in.
    tool : str
        The name of the tool to be run for logging.
    wd : str
        Sets the working directory for the decompiler.
    """
    if wd is None:
        wd = os.getcwd()
    with open(os.path.join(log_dir, 'stdout.log'), 'w+') as stdout_file:
        with open(os.path.join(log_dir, 'stderr.log'), 'w+') as stderr_file:
            process = Popen(args=args, stdout=stdout_file, stderr=stderr_file, cwd=wd)
            try:
                process.wait(timeout=TIMEOUT)
            except TimeoutExpired as e:
                LOGGER.error(f'{tool} timed out for {file_path.split("/")[-1]}')
                os.kill(process.pid, signal.SIGKILL)
                raise e


def parse_jadx(log_file):
    """Parses the log generated by jadx to discover methods that failed decompilation.

    Parameters
    ----------
    log_file : str
        The log file containing the failure information.

    Returns
    -------
    dict:
        The decompilation failure information containing:
        timeout : bool
            Always False as timeouts are caught before.
        methods : list
            A list of all failed methods, qualified with their class name.
    """
    jadx_results = dict()
    with open(log_file, 'r') as log:
        for line in log:
            line = line.strip()
            if ' errors occurred in following nodes:' in line:
                break
            if line.startswith('ERROR - ['):
                try:
                    info = line.split('] ', 1)[1]
                    reason, info = info.split(' in method: ', 1)
                    try:
                        info, details = info.split(', details: ', 1)
                    except ValueError:
                        info = info.split(', file:', 1)[0]
                        n = next(log).strip()
                        if n.startswith('ERROR') or n.startswith('INFO'):
                            log = itertools.chain([n], log)
                            details = "Failed to extract details"
                        else:
                            details = n
                    reason += f', details: {details}'
                    method = info.split(', file:', 1)[0]
                    method, ret_type = method.split(':')
                    method, args = method.split('(')
                    splits = method.split('.')
                    method = splits[-1]
                    class_ = '.'.join(splits[:-1])
                    method = method + '(' + args + ':' + ret_type
                    class_name, signature = standardize_jadx(class_, method)
                    jadx_results[signature] = reason
                except IndexError:
                    LOGGER.exception(f'Encountered an error while parsing jadx for {log_file}')
    return {'jadx': {
        'timeout': False,
        'methods': jadx_results
    }}


def jadx(apk_path, directory):
    """Runs the jadx decompiler on an apk.

    Parameters
    ----------
    apk_path : str
        The application to run the decompiler on.
    directory : str
        The base directory for logfiles and output

    Returns
    -------
    dict:
        The decompilation failure information
    """
    jadx_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools', 'jadx', 'build', 'jadx', 'bin',
                             'jadx')
    out = os.path.join(directory, 'decompiler', 'jadx')
    log_dir = os.path.join(out, 'logs')
    os.makedirs(log_dir, exist_ok=True)
    file_path = os.path.join(log_dir, 'stdout.log')
    jadx_args = [jadx_path, '--log-level', 'ERROR', '-d', out, '--no-res', '-j', '4', '--show-bad-code',
                 apk_path]
    try:
        run_decompiler(jadx_args, apk_path, log_dir, 'jadx')
    except TimeoutExpired:
        return {'jadx': {'timeout': True}}
    move = Popen(['mv sources files'], shell=True, cwd=out)
    try:
        move.wait(timeout=TIMEOUT)
    except TimeoutExpired:
        LOGGER.exception('Move command timed out')
        return parse_jadx(file_path)
    return parse_jadx(file_path)


def parse_cfr(out):
    """Parses the summary generated by cfr to discover methods that failed decompilation.

    Parameters
    ----------
    out : str
        The directory containing all cfr output

    Returns
    -------
    dict:
        The decompilation failure information containing:
        timeout : bool
            Always False as timeouts are caught before.
        methods : list
            A list of all failed methods, qualified with their class name.
    """
    cfr_results = dict()
    with open(os.path.join(out, 'summary.txt')) as summary:
        for line in summary:
            if line.startswith('FAILED_METHOD:'):
                rest, reason = line.split('FAILED_METHOD:\t')[-1].strip().split(';', 1)
                reason = reason.replace(';', '')
                class_name, signature = rest.split(' ', 1)
                cfr_results[standardize_cfr(class_name, signature)[1]] = reason
    return {'cfr': {
        'timeout': False,
        'methods': cfr_results
    }}


def cfr(jar_path, directory):
    """Runs the cfr decompiler on a jar.

    Parameters
    ----------
    jar_path : str
        The application to run the decompiler on.
    directory : str
        The base directory for logfiles and output

    Returns
    -------
    dict:
        The decompilation failure information
    """
    out = os.path.join(directory, 'decompiler', 'cfr')
    log_dir = os.path.join(out, 'logs')
    files_dir = os.path.join(out, 'files')
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)
    wd = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools', 'cfr', 'target',
                      'classes')
    cfr_args = ['java', 'org.benf.cfr.reader.Main', jar_path, '--outputdir', files_dir, '--silent']
    try:
        run_decompiler(cfr_args, jar_path, log_dir, 'cfr', wd)
    except TimeoutExpired:
        return {'cfr': {'timeout': True}}
    try:
        return parse_cfr(files_dir)
    except FileNotFoundError:
        return {'cfr': {'timeout': False, 'classes': {}}}


def parse_procyon(out):
    """Parses the files generated by procyon to discover methods that failed decompilation.

    Procyon does not provide a convenient log or summary file, instead we have to parse all files and look for comments.

    Parameters
    ----------
    out : str
        The directory containing the decompiled files.

    Returns
    -------
    dict:
        The decompilation failure information containing:
        timeout : bool
            Always False as timeouts are caught before.
        methods : list
            A list of all failed methods, qualified with their class name.
    list:
        The list of files with no failures as those can be removed.
    """
    LOGGER.debug('Started parsing procyon output')
    procyon_results = dict()
    files_to_remove = []
    for file in fnmatch.filter(glob.iglob(os.path.join(out, '**'), recursive=True), '*.java'):
        file_name = file.split(out)[-1][1:-5].replace('/', '.')
        found_error = False
        with open(file, 'r') as j_file:
            for line in j_file:
                if 'The method "' in line and '" could not be decompiled.' in line:
                    found_error = True
                    class_name, signature = standardize_procyon(file_name, line.split('"')[1])
                    procyon_results[signature] = line.strip().split("could not be decompiled. ")[1]
        if not found_error:
            files_to_remove.append(file)
    LOGGER.debug('Finished parsing procyon output')
    return {'procyon': {
        'timeout': False,
        'methods': procyon_results
    }}, files_to_remove


def procyon(jar_path, directory):
    """Runs the procyon decompiler on a jar.

    Parameters
    ----------
    jar_path : str
        The application to run the decompiler on.
    directory : str
        The base directory for logfiles and output

    Returns
    -------
    dict:
        The decompilation failure information
    list:
        The list of files that can be removed.
    """
    out = os.path.join(directory, 'decompiler', 'procyon')
    log_dir = os.path.join(out, 'logs')
    files_dir = os.path.join(out, 'files')
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)
    procyon_jar = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools', 'procyon', 'build',
                               'Procyon.Decompiler', 'libs', 'procyon-decompiler-1.0-SNAPSHOT.jar')
    procyon_args = ['java', '-jar', procyon_jar, '-jar', jar_path, '-o', files_dir, '--log-level', '3']
    try:
        run_decompiler(procyon_args, jar_path, log_dir, 'procyon')
    except TimeoutExpired:
        return {'procyon': {'timeout': True}}, []
    results, procyon_files = parse_procyon(files_dir)
    return results, procyon_files


def parse_fernflower(log_dir):
    """Parses the log file generated by fernflower to discover methods that failed decompilation.


    Parameters
    ----------
    log_dir : str
        The directory containing the log file.

    Returns
    -------
    dict:
        The decompilation failure information containing:
        timeout : bool
            Always False as timeouts are caught before.
        methods : list
            A list of all failed methods, qualified with their class name.
    """
    fernflower_results = dict()
    with open(os.path.join(log_dir, 'stdout.log'), 'r') as log_file:
        file_name = ''
        for line in log_file:
            if 'Decompiling class ' in line:
                file_name = line.strip().split('Decompiling class ')[1]
            elif "couldn't be decompiled." in line:
                signature = line.split('Method ')[1].split(" couldn't be decompiled.")[0].strip()
                class_name, signature = standardize_fernflower(file_name, signature)
                fernflower_results[signature] = next(log_file).strip()
    return {'fernflower': {
        'timeout': False,
        'methods': fernflower_results
    }}


def fernflower(jar_path, directory):
    """Runs the fernflower decompiler on a jar.

    Parameters
    ----------
    jar_path : str
        The application to run the decompiler on.
    directory : str
        The base directory for logfiles and output

    Returns
    -------
    dict:
        The decompilation failure information
    """
    out = os.path.join(directory, 'decompiler', 'fernflower')
    log_dir = os.path.join(out, 'logs')
    files_dir = os.path.join(out, 'files')
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(files_dir, exist_ok=True)
    fernflower_jar = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tools', 'fernflower', 'build',
                                  'libs', 'fernflower.jar')
    fernflower_args = ['java', '-Xmx4096m', '-jar', fernflower_jar, jar_path, files_dir]
    timeout = False
    try:
        run_decompiler(fernflower_args, jar_path, log_dir, 'fernflower')
    except TimeoutExpired:
        LOGGER.error(f'Fernflower timed out after {TIMEOUT} seconds for file {jar_path.split("/")[-1]}')
        timeout = True
#    convert = Popen(['jar xf *.jar; rm *.jar'], shell=True, cwd=files_dir)
#    try:
#        if convert.wait(TIMEOUT) != 0:
#    except TimeoutExpired:
#        LOGGER.exception(f'Unzippping and removing jar created by fernflower timed out')
    if timeout:
        result = parse_fernflower(log_dir)
        attrs = result.get('fernflower', {})
        attrs['timeout'] = True
        result['fernflower'] = attrs
        return result
    else:
        return parse_fernflower(log_dir)


def _handle_error(func, path, exc_info):
    """Instead of raising errors for shutil functions, log them and continue"""
    LOGGER.error(f'Failed to delete {path}')


def save_to_file(directory, package_name, result):
    """
    Saves the results as a .decre (DECompilation REsult) file

    Parameters
    ----------
    directory : str
        The directory the file will be saved to.
    package_name: str
        The name of the package this information is associated with.
    result : dict
        The errors produced by various decompiler.

    Returns
    -------
    str
    """
    file_name = os.path.join(directory, package_name + '.decre')
    with open(file_name, 'w') as file:
        json.dump(result, file, sort_keys=True, indent=4)
    return file_name


def reduce_size(directory, procyon_files, dex):
    """Reduces the size on disk by compressing the decompiler outputs and removing unnecessary files.

    At the moment, complete removal is necessary, as otherwise we will run out of disk space.

    Parameters
    ----------
    directory : str
        The directory all the files are located in.
    procyon_files : list
        A list of files generated by procyon with no failures.
    dex : bool
        If set, only dex decompilers were run and there are fewer files to be removed.
    """
    LOGGER.info(f'Removing generated outputs in directory {directory}')
    if dex:
        decompilers = ['jadx']
    else:
        shutil.rmtree(os.path.join(directory, 'dex2jar', 'files'), onerror=_handle_error)
        decompilers = ['cfr', 'jadx', 'fernflower']
        cfr_path = os.path.join(directory, 'decompiler', 'cfr')
        try:
            shutil.move(os.path.join(cfr_path, 'files', 'summary.txt'), os.path.join(cfr_path, 'logs', 'summary.txt'))
            os.remove(os.path.join(directory, 'apkanalyzer', 'methods.log'))
        except FileNotFoundError:
            LOGGER.error("CFR summary not found, probably decompilation was stopped by an apkanalyzer error.\n"
                         "Skipping further removal attempts.")
            return
        for file in procyon_files:
            os.remove(file)
        for root, dirs, files in os.walk(os.path.join(directory, 'decompiler', 'procyon', 'files'), topdown=False):
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except OSError:
                    pass
        shutil.rmtree(os.path.join(directory, 'decompiler', 'procyon', 'logs'), onerror=_handle_error)
    for decompiler in decompilers:
        shutil.rmtree(os.path.join(directory, 'decompiler', decompiler, 'files'), onerror=_handle_error)


def analyse_app(file, directory, package_name, out, category, downloads, dex):
    """Given an apk file, converts it to jar, checks for packers and runs decompilers and similarity analysis.

    Parameters
    ----------
    file : str
        The apk file to run the analysis on.
    directory : str
        The directory containing the file to put output and logfiles in a subdirectory.
    package_name : str
        The package name of the application to analyze.
    out : str
        The path of the folder to save the output to.
    category : str
        The name of the category (family in case of malware) the app belongs to.
    downloads : str
        The number of downloads an app has in string representation.
    dex : bool
        If set, only dex compatible decompilers will be run.
    Returns
    -------
    list:
        The list of decompiled procyon files with no failures. Those can be removed without losing any information
        (Provided no similarity analysis is run).
    bool:
        Whether the files should be preserved as they are.
        Necessary to avoid errors when reading existing decompilation information from file.
    """
    all_start = time.time()
    if os.path.exists(os.path.join(out, f'{package_name}.ecsv')):
        LOGGER.info(f'Found existing decompilation results')
        cfr_path = os.path.join(directory, 'decompiler', 'cfr', 'logs', 'summary.txt')
        jadx_path = os.path.join(directory, 'decompiler', 'jadx', 'logs', 'stdout.log')
        procyon_path = os.path.join(directory, 'decompiler', 'procyon', 'files')
        fernflower_path = os.path.join(directory, 'decompiler', 'fernflower', 'logs', 'stderr.log')
        exists = True
        for path in [cfr_path, jadx_path, procyon_path, fernflower_path]:
            if not os.path.exists(path):
                exists = False
                LOGGER.info('Existing sources were incomplete, rerunning decompilation')
                break
        if exists:
            return [], True
    del_directories = ['decompiler', 'dex2jar', 'apkid']
    for del_dir in del_directories:
        del_path = os.path.join(directory, del_dir)
        if os.path.exists(del_path):
            shutil.rmtree(del_path, onerror=_handle_error)
    if dex:
        decompile_dex(directory, file, package_name, out, category, downloads)
        LOGGER.info(f'Processing of {package_name} with dex decompilers took {time.time() - all_start} in total')
        return [], False
    else:
        procyon_files = decompile_apk(directory, file, package_name, out, category, downloads)
        LOGGER.info(f'Processing of {package_name} took {time.time() - all_start} in total')
        return procyon_files, False


def _create_methods(methods, dex_compatible, lookup, matches, timed_out, reasons):
    decompilers = ['cfr', 'fernflower', 'jadx', 'procyon']
    created_methods = set()
    for signature in methods.keys():
        csv_str = f'{signature};{methods[signature]};'
        csv_end = ""
        compatible = dex_compatible[signature]
        for decompiler in decompilers:
            if decompiler in timed_out:
                csv_str += 'T;'
                csv_end += 'T;'
            else:
                dex = compatible.get(decompiler, None)
                if not dex:
                    csv_str += 'N;'
                    csv_end += 'N;'
                    continue
                if dex in lookup[decompiler]:
                    dec_matches = matches[decompiler]
                    dec_matches[dex] = dec_matches[dex] + [signature]
                    matches[decompiler] = dec_matches
                    csv_str += 'F;'
                    csv_end += reasons.get(decompiler, dict()).get(dex, '') + ';'
                else:
                    csv_str += 'S;'
                    csv_end += 'S;'
        created_methods.add(Method(csv_str + csv_end))
    return created_methods, matches


def combine_results(decompiler_results, apk_analyzer_results, apk_path):
    data = {'size': os.path.getsize(apk_path),
            'method_count': apk_analyzer_results['method_count']
            }
    matches = dict()
    reasons = dict()
    timed_out = set()
    for decompiler in decompiler_results.keys():
        if decompiler_results[decompiler].get('timeout', False):
            timed_out.add(decompiler)
            matches[decompiler] = dict()
            continue
        methods = decompiler_results[decompiler].get('methods', dict())
        match = dict()
        reas = dict()
        for method in methods.keys():
            match[method] = []
            reas[method] = methods[method]
        matches[decompiler] = match
        reasons[decompiler] = reas
    dex_compatible = dict()
    methods = apk_analyzer_results['methods']
    signatures = methods.keys()
    for method in signatures:
        for decompiler in decompiler_results.keys():
            dex = dex_compatible.get(method, {})
            dex[decompiler] = CONVERT_DEX[decompiler](method)
            dex_compatible[method] = dex
    lookup = dict()
    for decompiler in decompiler_results.keys():
        lookup[decompiler] = set(matches[decompiler].keys())
    created_methods, debug_data = _create_methods(methods, dex_compatible, lookup, matches, timed_out, reasons)
    data['methods'] = created_methods
    return data, debug_data


def decompile_dex(directory, file, package_name, path, category, downloads):
    """Decompiles an apk with all dex decompilers present.

    Parameters
    ----------
    directory : str
        The parent directory for all logfiles and output.
    file : str
        The apk to decompile.
    package_name : str
        The package name of the apk, identifying it uniquely.
    downloads : str
        The number of app downloads represented as str.
    category : str
        The category of the application.
    path : str
        The path of the output folder.

    Returns
    -------
    """
    os.makedirs(os.path.join(directory, 'decompiler'), exist_ok=True)
    apk_path = file[:-3] + 'apk'
    if not os.path.exists(apk_path):
        raise APKError()
    apk_analyzer_dir = os.path.join(directory, 'apkanalyzer')
    os.makedirs(apk_analyzer_dir, exist_ok=True)
    try:
        LOGGER.info(f'Running apkanalyzer on {package_name}')
        apk_analyzer_results = run_apk_analyzer(apk_path, TIMEOUT, apk_analyzer_dir)
    except ApkAnalyzerError:
        LOGGER.error(f'APK {package_name} failed processing with apkanalyzer.')
        filewriter.apk_error(path, package_name)
        return
    packer_name = packer(apk_path, directory)
    LOGGER.info(f'Decompiling sources for {package_name} with jadx')
    decompiler_results = jadx(apk_path, directory)
    LOGGER.debug(decompiler_results)
    LOGGER.info(f'Finished decompiling {package_name} with all dex decompilers')
    combined_results, debug_data = combine_results(decompiler_results, apk_analyzer_results, apk_path)
    filewriter.results(path, packer_name, package_name, combined_results, decompiler_results, category, downloads)
    filewriter.debug(path, package_name, debug_data)


def decompile_apk(directory, file, package_name, path, category, downloads):
    """Decompiles an apk with all decompilers present.

    Parameters
    ----------
    directory : str
        The parent directory for all logfiles and output.
    file : str
        The apk to decompile.
    package_name : str
        The package name of the apk, identifying it uniquely.
    downloads : str
        The number of app downloads represented as str.
    category : str
        The category of the application.
    path : str
        The path of the output folder.

    Returns
    -------
    list:
        The list of procyon files with no failures.
    """
    os.makedirs(os.path.join(directory, 'decompiler'), exist_ok=True)
    apk_path = file[:-3] + 'apk'
    if not os.path.exists(apk_path):
        raise APKError()
    apk_analyzer_dir = os.path.join(directory, 'apkanalyzer')
    os.makedirs(apk_analyzer_dir, exist_ok=True)
    try:
        LOGGER.info(f'Running apkanalyzer on {package_name}')
        apk_analyzer_results = run_apk_analyzer(apk_path, TIMEOUT, apk_analyzer_dir)
    except ApkAnalyzerError:
        LOGGER.error(f'APK {package_name} failed processing with apkanalyzer.')
        filewriter.apk_error(path, package_name)
        return []
    LOGGER.info(f'Converting sources for {package_name} to jar')
    try:
        jar_path = dex2jar(apk_path, directory, package_name)
    except ConversionError:
        LOGGER.error(f'APK {package_name} encountered a conversion error.')
        filewriter.conversion_error(path, package_name)
        return []
    packer_name = packer(apk_path, directory)
    decompiler_results = {}
    LOGGER.info(f'Decompiling sources for {package_name} with jadx')
    jadx_result = jadx(apk_path, directory)
    decompiler_results.update(jadx_result)
    LOGGER.info(f'Decompiling sources for {package_name} with cfr')
    cfr_result = cfr(jar_path, directory)
    decompiler_results.update(cfr_result)
    LOGGER.info(f'Decompiling sources for {package_name} with procyon')
    procyon_result, procyon_files = procyon(jar_path, directory)
    decompiler_results.update(procyon_result)
    LOGGER.info(f'Decompiling sources for {package_name} with fernflower')
    fernflower_result = fernflower(jar_path, directory)
    decompiler_results.update(fernflower_result)
    LOGGER.debug(decompiler_results)
    LOGGER.info(f'Finished decompiling {package_name} with all decompilers')
    combined_results, debug_data = combine_results(decompiler_results, apk_analyzer_results, apk_path)
    filewriter.results(path, packer_name, package_name, combined_results, decompiler_results, category, downloads)
    filewriter.debug(path, package_name, debug_data)
    # failures = debug(decompiler_results, apk_analyzer_results)
    return procyon_files


def analyse(out, base_path, preserve_dirs, config, dex):
    """Analyses a collection of apk files regarding their decompilation failures.

    Parameters
    ----------
    out : str
        The path of the output directory.
    base_path : str
        The common base path for all apks.
    preserve_dirs : bool
        If set, does not remove output files afterwards.
        WARNING! This option will result in huge output.
    config : str
        Path to a configuration directory. Has to contain a file RUN, otherwise the analysis won't start.
        Used to stop the analysis gracefully if removed.
    dex : bool
        If set, only dex compatible decompilers will be run.

    Returns
    -------

    """
    pain_count = 0
    apk_count = 0
    all_similarities = []
    ready_files = []
    os.makedirs(config, exist_ok=True)
    try:
        with open(os.path.join(config, 'processed.json'), 'r') as processed_files:
            ready_files = json.load(processed_files).get('files')
            LOGGER.info(ready_files)
    except (FileNotFoundError, JSONDecodeError):
        LOGGER.info(f'No processed files found')
    initial = len(ready_files)
    os.makedirs(out, exist_ok=True)
    files = fnmatch.filter(glob.iglob(os.path.join(base_path, '**'), recursive=True), '*.apk')
    for file in files:
        if file in ready_files:
            continue
        try:
            app = App.from_file(file.replace('.apk', '.pain'))
            package_name = app.package_name()
            if app.store() == 'F-Droid':
                downloads = '-1'
            else:
                downloads = str(app.downloads())
            category = app.category_name()
            pain_count += 1
        except ConfigurationError as e:
            LOGGER.exception(e)
            continue
        except FileNotFoundError as e:
            LOGGER.debug(e)
            package_name = file.split('/')[-1][:-4]
            category = file.split('/')[-3]
            downloads = '-1'
        directory = os.path.dirname(file)
        LOGGER.info(f'Processing apk {package_name}')
        try:
            procyon_files, from_file = analyse_app(file, directory, package_name, out, category, downloads, dex)
            if from_file:
                initial += 1
            elif not preserve_dirs:
                reduce_size(directory, procyon_files, dex)
            apk_count += 1
            ready_files.append(file)
        except ConversionError:
            LOGGER.exception(f'Apk {package_name} failed to be converted to .jar format')
        except APKError:
            LOGGER.info(f'Apk {package_name} is not present')
        except Packer:
            LOGGER.info(f'Apk {package_name} was packed, skipping further analysis')
        # except:
        #     LOGGER.critical(f'Apk {package_name} encountered an unexpected error')
        try:
            open(os.path.join(config, 'RUN'), 'r')
        except FileNotFoundError:
            with open(os.path.join(config, 'processed.json'), 'w+') as processed_files:
                json.dump({'files': ready_files}, processed_files, sort_keys=True, indent=4)
                LOGGER.info(f'Interrupted processing after completing the analysis of {len(ready_files) - initial}'
                            f' files for a total of {len(ready_files)}')
                return all_similarities
    LOGGER.info(f'Found {pain_count:<5} apk_info files\n\t'
                f'and   {apk_count:<5} apk files in total\n\t'
                f'      {initial:<5} were analyzed beforehand')
    with open(os.path.join(config, 'processed.json'), 'w+') as processed_files:
        json.dump({'files': ready_files}, processed_files, sort_keys=True, indent=4)


def fix(out_path, base_path):
    files = fnmatch.filter(glob.iglob(os.path.join(base_path, '**'), recursive=True), '*.apk')
    for file in files:
        package_name = file.split('/')[-1][:-4]
        directory = os.path.dirname(file)
        LOGGER.info(f'Processing apk {package_name}')
        src = os.path.join(out_path, f'{package_name}.ecsv')
        if not os.path.exists(src):
            LOGGER.error(f'Did not find existing decompilation results')
            continue
        with open(src, 'r') as in_file:
            content = in_file.read().strip()
        if content.startswith('Packer'):
            LOGGER.info(f'No need to fix {package_name}')
            continue
        last_csv_header_line = 0
        current_line = 0
        for line in content.split('\n'):
            line = line.strip()
            if line == 'signature;size;C;F;J;P;C-R;F-R;J-R;P-R;':
                last_csv_header_line = current_line
            current_line += 1
        if last_csv_header_line != 7:
            content = '\n'.join(content.split('\n')[last_csv_header_line:])
        apk_analyzer_dir = os.path.join(directory, 'apkanalyzer')
        os.makedirs(apk_analyzer_dir, exist_ok=True)
        try:
            # LOGGER.info(f'Running apkanalyzer to fix {package_name}')
            apk_analyzer_results = run_apk_analyzer(file, TIMEOUT, apk_analyzer_dir)
        except ApkAnalyzerError:
            LOGGER.error(f'APK {package_name} failed processing with apkanalyzer.')
            filewriter.apk_error(file, package_name)
            continue
        packer_name = packer(file, directory)
        out = f'Packer:\t{packer_name}\n' \
              f'Methods:\t{apk_analyzer_results.get("method_count", -1)}\n' \
              f'Size:\t{os.path.getsize(file)}\n' \
              f'Downloads:\t-1\n' \
              f'Family:\tandrozoo\n' \
              f'##########\n\n' \
              f'{content}\n'
        with open(os.path.join(out_path, f'{package_name}.ecsv'), 'w') as out_file:
            out_file.write(out)
        LOGGER.info(f'Fixed {package_name}')
