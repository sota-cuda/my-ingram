import importlib
import os
from collections import defaultdict

from .base import POCTemplate


# Active scanner scope. Other PoC files remain in this directory for
# reference, but are not imported or executed by the scanner.
ENABLED_POC_MODULES = {
    'dahua-disabled',
    'dahua-weak-password',
    'hikvision-weak-password',
    'cve-2017-7921',
    'cve-2021-33044',
    'cve-2021-33045',
    'cve-2021-36260',
}


for file in os.listdir(os.path.dirname(__file__)):
    file_name, extension = os.path.splitext(file)
    if (
        extension == '.py'
        and file_name in ENABLED_POC_MODULES
    ):
        importlib.import_module(f'.{file_name}', 'Ingram.pocs')


def get_poc_dict(config):
    """Build the active PoC map for the configured Dahua/Hikvision scope."""
    poc_dict = defaultdict(list)
    enabled_products = getattr(config, 'enabled_products', {'dahua', 'hikvision'})
    for POC in POCTemplate.poc_classes:
        poc = POC(config)
        if poc.product in enabled_products:
            poc_dict[poc.product].append(poc)
    return poc_dict
