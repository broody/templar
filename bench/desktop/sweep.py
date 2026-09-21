from pathlib import Path
from bench import benchmark
ROOT=Path(__file__).resolve().parent
for family,counts in [('native',[1,2,4,8,16,32,64,256]),('felt',[1,2,4,8,16,32])]:
    for count in counts:
        result=benchmark(ROOT/'cases'/f'{family}-{count}')
        if not result.get('completed'):
            print(f'Stopping {family} after bounded failure at {count} pair hashes.',flush=True)
            break
