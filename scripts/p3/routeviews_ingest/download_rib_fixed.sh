#!/bin/bash

YEAR=2026
MONTH=01

BASE="http://archive.routeviews.org/bgpdata/${YEAR}.${MONTH}/RIBS/"

mkdir -p data/bgp/routeviews/ribs

wget -r -np -nd -A "*.bz2" $BASE -P data/bgp/routeviews/ribs
