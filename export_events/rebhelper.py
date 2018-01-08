import re

# Antelope Linux_a2  REB - Event        2  Muntenia, judetul Braila                                        Op: Daniel Paulescu
# Antelope Linux_a2  REB - Event        6  Zona seismica Vrancea, judetul Vrancea;  I0 = I                 Op: Laura Petrescu
# Antelope Linux_a2  REB - Event        6  Zona seismica Vrancea, judetul Vrancea                          Op: Laura Petrescu
header = re.compile('^Antelope .*- Event\s+\d+\s+([\w,\s-]+);?(?:\s+I0 = ([IXV]+)\s+)?(?:\s+Op: (.*))?$')

def trystrip(arg):
    try:
        return arg.strip()
    except:
        return arg

def parse_header(rebpath):

    with open(rebpath, 'rb') as f:
        for line in f:
            if line.startswith('Antelope'):
                break
        
        m = header.match(line)
        region, intensity, operator = map(trystrip, m.groups())
        return region, intensity, operator
