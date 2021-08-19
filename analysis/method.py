from analysis.apkanalyzer import dex_for_cfr, dex_for_fernflower, dex_for_jadx, dex_for_procyon


def _get_result(signature, results):
    if results is None:
        return 'E'
    elif results.get('timeout', False):
        return 'T'
    elif signature in results.get('methods', []):
        return 'F'
    else:
        return 'S'


class Method(object):

    def __init__(self, csv_str):
        self.signature, self.size, self.cfr, self.fernflower, self.jadx, self.procyon, self.cfr_reason, \
        self.fernflower_reason, self.jadx_reason, self.procyon_reason, ignored = csv_str.split(';', 10)

    def __str__(self):
        return f'{self.signature};{self.size};{self.cfr};{self.fernflower};{self.jadx};{self.procyon};' \
               f'{self.cfr_reason};{self.fernflower_reason};{self.jadx_reason};{self.procyon_reason};\n'

    def __lt__(self, other):
        return self.signature < other.signature

    def add_decompiler_info(self, results):
        normalize = {
            'cfr': dex_for_cfr,
            'fernflower': dex_for_fernflower,
            'jadx': dex_for_jadx,
            'procyon': dex_for_procyon,
        }
        decompilers = ['cfr', 'fernflower', 'jadx', 'procyon']
        for decompiler in decompilers:
            normalized = normalize[decompiler](self.signature)
            result = results.get(decompiler, None)
            code = _get_result(normalized, result)
            setattr(self, decompiler, code)
