#!/bin/bash
mvn compile test-compile package install -D maven.test.skip=true -P product
