#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# A quick-and-dirty test to deduce the appropriate SimHash distance to use with a
# MISP dataset (per type). The idea is to analyse existing types and defines a
# specific SimHash distance depending of the attribute type (such as sigma,
# yara, text, comment or what ever type supported) in MISP when the correlation
# engine will support it.
#
# Software licensed under the AGPL version 3 or later.
#
# Copyright (C) 2018 Alexandre Dulaunoy - a@foo.be

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
from simhash import Simhash
import redis

r = redis.Redis(host='localhost', port=6380, encoding='utf-8', decode_responses=True)

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

def search(m, quiet, url, out=None, custom_type_attribute="text",
           default_distance=19, skip=False):
    controller = 'attributes'
    result = m.search(controller, type_attribute=custom_type_attribute)

# Redis data structure
# v: (key/value) -> values of a specific uuid
# r: (zrank) -> a set ranked by the SimHash distance of an attribute value
#               compared to other attribute value
# all (set) -> all uuid analysed
# all_hits (set) -> all uuid matching the SimHash distance set
# hits (key - counter) -> number of times a distance is matched between two
# attributes values
# missed (key - counter) -> number of times a distance is not matched between
# two attributes values

    for e in result['response']['Attribute']:
        r.sadd("all", e['uuid'])
        r.set("v:{}".format(e['uuid']), e['value'])

        for att in r.smembers("all"):
            if not quiet:
                print(att)
            if att != e['uuid']:
                att_value = r.get("v:{}".format(att))
                distance = Simhash(e['value']).distance(Simhash(att_value))
                if distance > default_distance:
                    r.incr('missed')
                    continue
                r.incr('hits')
                r.sadd('all_hits', e['uuid'])
                r.zadd('r:{}'.format(e['uuid']), '{}:{}'.format(e['event_id'], att), distance)
            else:
                print("don't compare self values")




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get all the attributes in MISP and calculate the SimHash distance')
    parser.add_argument("-q", "--quiet", action='store_true', help="Only display URLs to MISP")
    parser.add_argument("-s", "--skip", action='store_true', help="Skip duplicate match from same MISP event", default=False)
    parser.add_argument("-t", "--type", default='text')
    parser.add_argument("-d", "--distance", default=19, type=int)
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abort.')
        exit(0)

    misp = init(misp_url, misp_key)

    search(misp, args.quiet, misp_url, args.output, custom_type_attribute=args.type, default_distance=args.distance, skip=args.skip)
