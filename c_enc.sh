#!/bin/sh

xclip -selection c -o | ./clipenc -e | xclip -selection c