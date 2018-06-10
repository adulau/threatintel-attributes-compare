
# threatintel-attributes-compare

A quick-and-dirty test to deduce the appropriate SimHash distance to use with a [MISP](https://github.com/MISP/MISP) dataset (per type). The idea is to analyse existing types and defines a
specific [SimHash](http://www.wwwconference.org/www2007/papers/paper215.pdf) distance depending of the attribute type (such as sigma, yara, text, comment or what ever type supported) in MISP when the correlation engine will support it.


# Usage

~~~~
python3 build_similarities.py  --quiet --type=yara --distance=10
~~~~

# Requirements

- Redis
- SimHash Python library
- PyMISP
