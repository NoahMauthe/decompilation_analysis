import json
import os


def results(path, packer, package_name, data, results, category, downloads):
    file_path = os.path.join(path, f'{package_name}.ecsv')
    with open(file_path, 'w') as file:
        file.write(f'Packer:\t{packer}\n')
        file.write(f'Methods:\t{len(data["methods"])}\n')
        file.write(f'Size:\t{data["size"]}\n')
        file.write(f'Downloads:\t{downloads}\n')
        file.write(f'Family:\t{category}\n')
        file.write('#' * 10 + '\n\n')
        file.write('signature;size;C;F;J;P;\n')
        for method in data['methods']:
            file.write(str(method))
    with open(os.path.join(path, f'{package_name}.json'), 'w') as file:
        json.dump(results, file, indent=4, sort_keys=True)


def debug(path, package_name, debug_data):
    directory = os.path.join(path, 'debug')
    os.makedirs(directory, exist_ok=True)
    file_path = os.path.join(directory, f'{package_name}.debug')
    with open(file_path, 'w') as file:
        json.dump(debug_data, file, indent=4, sort_keys=True)


def apk_error(path, package_name):
    with open(os.path.join(path, f'{package_name}.ecsv'), 'w') as file:
        file.write(f'ERROR:\tApkanalyzer failed processing\n')


def conversion_error(path, package_name):
    with open(os.path.join(path, f'{package_name}.ecsv'), 'w') as file:
        file.write(f'ERROR:\tConversion to .jar using dex2jar failed\n')
