#!/bin/bash

# Run all the unit tests and create a coverage report.

COVERAGE_REPORT_DIR=/tmp/vpc-router-coverage
nosetests -v --with-coverage --cover-erase \
          --cover-html --cover-html-dir=$COVERAGE_REPORT_DIR \
          --cover-package vpcrouter

echo "@@@ Coverage report: file://$COVERAGE_REPORT_DIR/index.html"
echo
