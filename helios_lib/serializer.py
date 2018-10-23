import inspect
import json
import sys
from json import JSONDecoder

sys.path.insert(0, '../')

from helios_lib.models import HeliosElection
from helios_lib.config import ELGAMAL_PARAMS


def get_attributes(obj):
    attrs = inspect.getmembers(obj, lambda a: not (inspect.isroutine(a)))
    return dict([a for a in attrs if not (a[0].startswith('__') and a[0].endswith('__'))])


class HeliosTrusteeSerializer(json.JSONEncoder):
    def default(self, obj):
        # print('obj', obj, type(obj))
        # print('---------------')
        return (obj).__class__.__name__, get_attributes(obj)


class HeliosTrusteeDeSerializer(JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        return obj


class Example:
    d = None
    e = None


class Sample:
    a = None
    b = None
    c = None

    def __init__(self):
        self.a = 1
        self.c = Example()
        self.c.d = 1


helios_election = HeliosElection()
helios_trustee = helios_election.generate_helios_trustee(ELGAMAL_PARAMS)
sample = Sample()

x = json.dumps(helios_trustee, cls=HeliosTrusteeSerializer)
# print('x', type(x))

y = json.loads(x, cls=HeliosTrusteeDeSerializer)
# print((y))

