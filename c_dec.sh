#!/bin/sh

xclip -selection c -o | ./clipenc -d | xclip -selection c