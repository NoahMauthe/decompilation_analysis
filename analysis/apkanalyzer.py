import fnmatch
import glob
import json
import logging
import os
import subprocess

LOGGER = logging.getLogger('analysis.apkanalyzer')
APKANLYZER_PATH = '/opt/android-sdk/cmdline-tools/latest/bin/apkanalyzer'


class ApkAnalyzerError(Exception):
    pass


class StandardizeException(Exception):
    pass


def init_logging(logger):
    """Initialize the logger for this file as a child of the supplied one.

    This method should be called before using any other functionality if log output is desired.

    Parameters
    ----------
    logger : logging.Logger
        the parent logger to create a child of.
    """
    global LOGGER
    LOGGER = logging.getLogger(f'{logger.name}.{__name__}')
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.debug(f'Initialized logger {LOGGER.name}')


def process_size(size):
    """Computes a size in byte from a string.

    Allowed units for the size are 'B' for byte, 'KB' for kilobyte and 'MB' for megabyte.

    Parameters
    ----------
    size : str
        The size with its unit as a string.

    Returns
    -------
    int
        The size in bytes.
    """
    if 'MB' in size:
        return int(float(size.replace('MB', '')) * 1024 * 1024)
    elif 'KB' in size:
        return int(float(size.replace('KB', '')) * 1024)
    elif 'B' in size:
        return int(size.replace('B', ''))


def parse_cfr_args(args):
    """Converts method arguments as created by CFR to a format comparable to the one by apkanalyzer.

    Parameters
    ----------
    args : str
        Method arguments as created by the CFR decompiler.

    Returns
    -------
    str
        The arguments represented in an apkanalyzer compatible format.
    """
    arguments = ''
    braces = 0
    for char in args:
        if char == '<':
            braces += 1
        elif char == '>':
            if braces <= 0:
                LOGGER.error(f'Found closing brace without opening\n{args}')
            else:
                braces -= 1
        elif braces > 0:
            continue
        elif char == ' ':
            arguments += ','
        else:
            arguments += char
    try:
        if arguments[-1] == ',':
            return arguments[:-1]
    except IndexError:
        pass
    return arguments


def standardize_cfr(class_name, method_signature):
    """Converts a CFR-style method signature to an apkanalyzer compatible one.
    
    Parameters
    ----------
    class_name : str
        A CFR-style classname.
    method_signature: str
        A CFR-style method signature.
    Returns
    -------
    class_name : str
        An apkanalyzer-style classname.
    str:
        An apkanalyzer-style method signature.
    """
    method_signature = method_signature.strip()
    try:
        method_signature, args = method_signature.split('(', 1)
        method_signature = method_signature.strip()
        splits = method_signature.split(' ')
        name = splits[-1]
        if name == '<init>' or name == '<clinit>':
            method_signature = name
        else:
            method_signature = remove_braces(''.join(splits[:-1])) + ' ' + name
    except ValueError as e:
        LOGGER.error(f'Processing cfr type failed for\t{class_name} {method_signature}')
        raise ValueError(e)
    args = args.split(')')[0]
    arguments = parse_cfr_args(args)
    return class_name, f'{class_name} {method_signature}({arguments})'


def standardize_jadx(class_name, method_signature):
    """Converts a jadx-style method signature to an apkanalyzer compatible one.
    
    Parameters
    ----------
    class_name : str
        A jadx-style classname.
    method_signature: str
        A jadx-style method signature.
        
    Returns
    -------
    class_name : str
        An apkanalyzer-style classname.
    str:
        An apkanalyzer-style method signature.
    """
    method, return_type = method_signature.split('):', 1)
    method = method.replace(" ", "")
    method = method.replace('Eextends', '') # Workaround for very specific jadx related error.
    try:
        method_name, args = method.split('(', 1)
    except ValueError:
        LOGGER.error(f'Processing jadx type failed for\t{class_name} {method_signature}')
        return class_name, f'{class_name} {method_signature}'
    arguments = remove_braces(args)
    class_name = class_name.replace('$', '.')
    method_name = method_name.strip()
    if method_name == '<init>' or method_name == '<clinit>':
        return class_name, f'{class_name} {method_name}({arguments})'
    else:
        return class_name, f'{class_name} {remove_braces(return_type)} {method_name}({arguments})'


def remove_braces(string):
    """Removes everything enclosed in '<>' from a string.

    As apkanalyzer removes this information, all our decompilers need to be remove it as well.

    Parameters
    ----------
    string : str
        A string to remove braces from.
    Returns
    -------
    str:
        The string without the braces and everything enclosed.
    """
    arguments = ''
    braces = 0
    for char in string:
        if char == '<':
            braces += 1
        elif char == '>':
            if braces <= 0:
                LOGGER.error(f'Found closing brace without opening\n{string}')
            else:
                braces -= 1
        elif braces > 0:
            continue
        else:
            arguments += char
    try:
        if arguments[-1] == ',':
            return arguments[:-1]
    except IndexError:
        pass
    return arguments


def _process_procyon_types(class_name, method_signature):
    """Resolves the types in a procyon-style signature and converts them to an apkanalyzer compatible format.

    Parameters
    ----------
    class_name: str
        A procyon-style classname.
    method_signature : str
        A procyon-style method signature.

    Returns
    -------
    str
        An apkanalyzer compatible signature with resolved types.
    """
    method_signature = method_signature.replace('public ', ''). \
        replace('final ', ''). \
        replace('abstract ', ''). \
        replace('private ', ''). \
        replace('static ', ''). \
        replace('protected ', '')
    method_signature = method_signature.replace(', ', ',').strip()
    try:
        method_type, method_signature = method_signature.split(' ', 1)
        method_name, args = method_signature.split('(', 1)
    except ValueError:
        LOGGER.error(f'Processing procyon type failed for\t{class_name} {method_signature}')
        return f'{class_name} {method_signature}'
    args = remove_braces(args.replace(' ', '')).replace('...', '[]').replace('$', '.')
    method_type = remove_braces(method_type).replace('$', '.')
    if method_name == '<init>' or method_name == '<clinit>':
        return f'{class_name} {method_name}({args}'
    else:
        return f'{class_name} {method_type} {method_name}({args}'


def standardize_procyon(class_name, method_signature):
    """Converts a procyon-style method signature to an apkanalyzer compatible one.

    procyon does not provide fully qualified types, so they will have to be altered in the apkanalyzer output when
    comparing.

    Parameters
    ----------
    class_name : str
        A procyon-style classname.
    method_signature: str
        A procyon-style method signature.

    Returns
    -------
    class_name : str
        An apkanalyzer-style classname.
    str
        An apkanalyzer-style method signature.
    """
    if method_signature == '':
        return class_name, method_signature
    class_name = class_name.replace('/', '.')
    method_signature = _process_procyon_types(class_name, method_signature)
    return class_name, method_signature


def _process_fernflower_array_type(type_string):
    """Converts a fernflower-style array-type to an apkanalyzer compatible one.

    Should only be called by _process_fernflower_type.

    Parameters
    ----------
    type_string : str
        A fernflower-style array-type.

    Returns
    -------
    str
        An apkanalyzer compatible array-type.
    """
    if type_string.startswith('L'):
        return type_string[1:].replace('/', '.')
    elif type_string.startswith('['):
        type_string = type_string[1:]
        return f'{_process_fernflower_array_type(type_string)}[]'
    elif type_string.startswith('I'):
        return 'int'
    elif type_string.startswith('V'):
        return 'void'
    elif type_string.startswith('Z'):
        return 'boolean'
    elif type_string.startswith('J'):
        return 'long'
    elif type_string.startswith('B'):
        return 'byte'
    elif type_string.startswith('F'):
        return 'float'
    elif type_string.startswith('C'):
        return 'char'
    elif type_string.startswith('D'):
        return 'double'
    elif type_string.startswith('S'):
        return 'short'
    else:
        return type_string[0]


def _process_fernflower_type(type_string):
    """Converts a fernflower-style type to an apkanalyzer compatible one.

    As fernflower-style types may include multiple types in one string, there may be multiple ones for one type_string.

    Parameters
    ----------
    type_string : str
        A fernflower-style type.

    Returns
    -------
    str
        An apkanalyzer compatible type.
    """
    type_string = type_string.replace(';', '').strip()
    if type_string == '':
        return ''
    elif type_string.startswith('L'):
        return type_string[1:].replace('/', '.')
    elif type_string.startswith('['):
        if len(type_string) > 2 and type_string[1] != 'L' and type_string[1] != '[':
            return f'{_process_fernflower_array_type(type_string[1:])}[],{_process_fernflower_type(type_string[2:])}'
        else:
            return f'{_process_fernflower_array_type(type_string[1:])}[]'
    elif type_string.startswith('I'):
        if len(type_string) > 1:
            return f'int,{_process_fernflower_type(type_string[1:])}'
        else:
            return 'int'
    elif type_string.startswith('V'):
        if len(type_string) > 1:
            return f'void,{_process_fernflower_type(type_string[1:])}'
        else:
            return 'void'
    elif type_string.startswith('Z'):
        if len(type_string) > 1:
            return f'boolean,{_process_fernflower_type(type_string[1:])}'
        else:
            return 'boolean'
    elif type_string.startswith('J'):
        if len(type_string) > 1:
            return f'long,{_process_fernflower_type(type_string[1:])}'
        else:
            return 'long'
    elif type_string.startswith('B'):
        if len(type_string) > 1:
            return f'byte,{_process_fernflower_type(type_string[1:])}'
        else:
            return 'byte'
    elif type_string.startswith('F'):
        if len(type_string) > 1:
            return f'float,{_process_fernflower_type(type_string[1:])}'
        else:
            return 'float'
    elif type_string.startswith('D'):
        if len(type_string) > 1:
            return f'double,{_process_fernflower_type(type_string[1:])}'
        else:
            return 'double'
    elif type_string.startswith('S'):
        if len(type_string) > 1:
            return f'short,{_process_fernflower_type(type_string[1:])}'
        else:
            return 'short'
    elif type_string.startswith('C'):
        if len(type_string) > 1:
            return f'char,{_process_fernflower_type(type_string[1:])}'
        else:
            return 'char'
    else:
        LOGGER.error(type_string)


def standardize_fernflower(class_name, method_signature):
    """Converts a fernflower-style method signature to an apkanalyzer compatible one.

    Parameters
    ----------
    class_name : str
        A fernflower-style classname.
    method_signature: str
        A fernflower-style method signature.

    Returns
    -------
    class_name : str
        An apkanalyzer-style classname.
    str
        An apkanalyzer-style method signature.
    """
    class_name = class_name.replace('/', '.').split('$')[0]
    method_signature = method_signature.strip()
    try:
        name, args = method_signature.split(' ', 1)
        args, return_type = args.split(')')
    except ValueError:
        LOGGER.error(f'Processing fernflower type failed for\t{class_name} {method_signature}')
        return class_name, f'{class_name} {method_signature}'
    return_type = _process_fernflower_type(return_type)
    args = args.split('(')[-1]
    if name in ['<init>', '<clinit>']:
        signature = f'{class_name} {name}('
    else:
        signature = f'{class_name} {return_type} {name}('
    if args == '':
        return class_name, signature + ')'
    for arg_type in args.split(';'):
        if arg_type == '':
            continue
        processed = _process_fernflower_type(arg_type)
        signature += processed
        signature += ','
    return class_name, signature[:-1] + ')'


def dex_for_fernflower(signature):
    """Converts an apkanalyzer-style signature to a fernflower compatible one.

    As fernflower does not distinguish between methods from inner and outer classes, quantification of the classname
    needs to stop at the first '$'.

    Parameters
    ----------
    signature: str
        An apkanalyzer-style signature.

    Returns
    -------
    str
        A fernflower compatible signature.
    """
    class_name, method_name = signature.split(' ', 1)
    if '$' in class_name:
        class_name = class_name.split('$')[0]
    return f'{class_name} {method_name}'


def dex_for_jadx(signature):
    """Converts an apkanalyzer-style signature to a jadx compatible one.

    As jadx does not distinguish between inner classes and regular ones, every '$' is changed to a '.'.

    Parameters
    ----------
    signature: str
        An apkanalyzer-style signature.

    Returns
    -------
    str
        A jadx compatible signature.
    """
    class_name, method_name = signature.split(' ', 1)
    class_name = class_name.replace('$', '.')
    return f'{class_name} {method_name}'


def dex_for_cfr(signature):
    """Converts an apkanalyzer-style signature to a CFR compatible one.

    As CFR does not supply a return type, it will be omitted.
    
    Parameters
    ----------
    signature: str
        An apkanalyzer-style signature.

    Returns
    -------
    str
        A CFR compatible signature.
    """
    return signature


def dex_for_procyon(signature):
    """Converts an apkanalyzer-style signature to a procyon compatible one.

    As procyon does not quantify types, all quantification is removed.

    Parameters
    ----------
    signature: str
        An apkanalyzer-style signature.

    Returns
    -------
    str
        A procyon compatible signature.
    """
    class_, signature = signature.split(' ', 1)
    class_ = class_.split('$')[0]
    return class_ + ' ' + signature.replace('$', '.')  # + '(' + args.replace('$', '.')


def compute_revised_failures(data, decre_file, compute_size):
    """Computes the method sizes for all failures and creates new decompilation results with them attached.

    Parameters
    ----------
    data : dict
        The method information created by apkanalyzer.
    decre_file : str
        The path to the old decompilation results file.
    compute_size : bool
        If true, sizes will be computed for each failure.
        Otherwise, only the overall method count will be added to the output.

    Returns
    -------
    results : dict
        The updated failure information.
    """
    results = {'total_methods': data['method_count']}
    try:
        with open(decre_file, 'r') as file:
            decre = json.load(file)
    except FileNotFoundError:
        LOGGER.error(f'File {decre_file} had no decompilation results')
        return results
    if decre.get('packer', False):
        decre.update(results)
        return decre
    if compute_size:
        try:
            results = _compute_size(data, decre, results)
        except StandardizeException as e:
            LOGGER.exception(e)
            decre.update(results)
            return decre
    return results


def _compute_size(data, decre, results):
    """Computes the size of the each failure and adds it as information to results.

    Parameters
    ----------
    data : dict
        The method information as created by apkanalyzer.
    decre : dict
        The decompilation results to retrieve the sizes for.
    results : dict
        A pre-initialized dict to update with the sizes.

    Returns
    -------
    results : dict
        The failure information with sizes attached.
    """
    standardize = {
        'cfr': standardize_cfr,
        'jadx': standardize_jadx,
        'procyon': standardize_procyon,
        'fernflower': standardize_fernflower
    }
    cfr_lookup = {}
    fernflower_lookup = {}
    jadx_lookup = {}
    procyon_lookup = {}
    lookup = {
        'cfr': cfr_lookup,
        'jadx': jadx_lookup,
        'procyon': procyon_lookup,
        'fernflower': fernflower_lookup
    }
    data = data['methods']
    for dat in data.keys():
        cfr_lookup[dex_for_cfr(dat)] = data[dat]
        jadx_lookup[dex_for_jadx(dat)] = data[dat]
        procyon_lookup[dex_for_procyon(dat)] = data[dat]
        fernflower_lookup[dex_for_fernflower(dat)] = data[dat]
    for decompiler_name in ['cfr', 'procyon', 'jadx', 'fernflower']:
        failed = 0
        decompiler = decre.get(decompiler_name, {})
        result_decompiler = results.get(decompiler_name, {})
        result_decompiler['timeout'] = decompiler.get('timeout', False)
        if decompiler.get('timeout', False):
            results[decompiler_name] = decompiler
        classes = decompiler.get('classes', {})
        result_classes = result_decompiler.get('classes', {})
        for class_name in classes.keys():
            methods = classes.get(class_name, {})
            result_methods = result_classes.get(class_name, {})
            for method_name in methods.keys():
                if method_name == '':
                    continue
                try:
                    class_name, method_name = standardize[decompiler_name](class_name, method_name)
                except Exception as e:
                    raise StandardizeException(f'Standardizing failed in unexpected ways for {decompiler_name} -'
                                               f' {class_name} {method_name}')
                size = lookup[decompiler_name].get(f'{method_name.strip()}', -1)
                result_methods[method_name] = size
                failed += 1
            result_classes[class_name] = result_methods
        result_decompiler['classes'] = result_classes
        result_decompiler['failed_methods'] = failed
        results[decompiler_name] = result_decompiler
    return results


def run_analysis(args):
    """Analyzes a collection of apk files regarding their method count.

    Additionally incorporates .decre files to match methods that failed decompilation to their sizes.
    The information is directly saved to a file per apk, thus no data is returned

    Parameters
    ----------
    args : argparse.Namespace
        The user supplied program arguments
    """
    processed = 0
    total_failed_size = 0
    total_failed_method_count = 0
    total_method_count = 0
    total_failed_apps = 0
    for apk in fnmatch.filter(glob.iglob(os.path.join(args.path, '**'), recursive=True), '*.apk'):
        try:
            folder_name = os.path.join(os.path.sep.join(apk.split(os.path.sep)[:-1]), 'methods_analysis')
            os.makedirs(folder_name, exist_ok=True)
            try:
                data = run_apk_analyzer(apk, args.timeout, folder_name)
            except ApkAnalyzerError:
                LOGGER.exception(f'{apk} failed processing by apkanalyzer')
                continue
            splits = apk.split(os.path.sep)
            decre = os.path.join(os.path.sep.join(splits[:-1]), splits[-2] + '.decre')
            results = compute_revised_failures(data, decre, args.size)
            if args.size:
                with open(decre[:-5] + 'extended_decre_with_size', 'w') as file:
                    json.dump(results, file, indent=4, sort_keys=True)
            else:
                with open(decre[:-5] + 'extended_decre', 'w') as file:
                    json.dump(results, file, indent=4, sort_keys=True)
            failed_size = 0
            failed_method_count = 0
            method_count = results['total_methods']
            for decompiler in ['cfr', 'procyon', 'jadx', 'fernflower']:
                classes = results.get(decompiler, {}).get('classes', {})
                for class_name in classes:
                    methods = classes[class_name]
                    failed_method_count += len(methods)
                    for method in methods:
                        if methods[method] == -1:
                            failed_size += 1
            del results
            total_failed_size += failed_size
            total_failed_method_count += failed_method_count
            total_method_count += method_count
            if failed_size > 0:
                LOGGER.error(f'Out of {method_count}, {failed_method_count} methods failed decompilation\n'
                             f'Out of {failed_method_count}, {(failed_size / max(failed_method_count, 1)) * 100}%'
                             f' ({failed_size}) did not return a size')
                total_failed_apps += 1
            processed += 1
            if processed % 10 == 0:
                LOGGER.info(f'{"#" * 40}\n'
                            f'Processed {processed} apks so far, {(total_failed_apps / processed) * 100:.4f}% '
                            f'({total_failed_apps}) of which had size failures\n\n'
                            f'Out of {total_method_count} methods in {processed} apps, '
                            f'{(total_failed_method_count / total_method_count) * 100:.4f}% '
                            f'({total_failed_method_count}) failed decompilation\n'
                            f'Out of those {total_failed_method_count} methods, '
                            f'{(total_failed_size / total_failed_method_count) * 100:.4f}% ({total_failed_size})'
                            f' methods failed to retrieve a size\n'
                            f'{"#" * 40}')
        except Exception as e:
            LOGGER.fatal(e)


def run_apk_analyzer(apk, timeout, directory):
    """Runs the apkanalyzer tool (part of the Android SDK) to retrieve method information from an apk.

    Parameters
    ----------
    apk : str
        The path of the apk to analyze.
    timeout : int
        The timeout in seconds for the tool. Can be altered by the user via commandline argument --timeout
    directory : str
        The path of the folder to save all outputs to

    Returns
    -------
    dict
        A dict containing the following results:
            {
                'method_count': 'Total number of methods in the apk',
                'methods': 'A dict mapping method signatures to their sizes'
            }
    """
    methods = {}
    file_name = os.path.join(directory, 'methods.log')
    with open(file_name, 'w') as out_file:
        save_apk = apk.replace('(', '\\(').replace(')', '\\)')
        arguments = f'{APKANLYZER_PATH} -h dex packages --defined-only {save_apk} | grep -e "^M"'
        LOGGER.debug(arguments)
        p = subprocess.Popen(arguments, stdout=out_file, shell=True)
        try:
            p.wait(timeout)
        except subprocess.TimeoutExpired:
            LOGGER.error(f'Computing methods timed out for {apk}')
            raise ApkAnalyzerError(f'{apk} failed')
        if p.returncode != 0:
            p.kill()
            raise ApkAnalyzerError(f'{apk} failed')
    with open(file_name, 'r') as file:
        for line in file:
            line = line.strip()
            try:
                line = line.split('M d ', 1)[1]
            except IndexError:
                LOGGER.error(line)
                continue
            declared, referenced, size, name = line.split('\t')
            size = size.strip()
            name = name.strip()
            if int(referenced) != 1:
                LOGGER.info(f'Method {name} in {apk} referenced {referenced} methods')
            size = process_size(size)
            methods[name] = size
    results = {'method_count': len(methods),
               'methods': methods,
               }
    with open(os.path.join(directory, 'apk_analyzer_results.json'), 'w') as json_file:
        json.dump(results, json_file, indent=4, sort_keys=True)
    return results
