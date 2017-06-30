#!/bin/bash

COVERAGE_REPORT_DIR=/tmp/vpc-router-coverage
nosetests -v --with-coverage --cover-erase \
          --cover-html --cover-html-dir=$COVERAGE_REPORT_DIR \
          --cover-package utils \
          --cover-package errors \
          --cover-package vpc \
          --cover-package watcher \
          --cover-package monitor

echo "@@@ Coverage report: file://$COVERAGE_REPORT_DIR/index.html"
