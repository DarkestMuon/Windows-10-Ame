#!/bin/bash

mkdir "empty_files"
cd "empty_files"
FILE_EXT=(doc docx gif json flac mkv pdf pps ppsx ppt pptx xls xlsx)
for ext in "${FILE_EXT[@]}"
do
	touch "$ext.$ext"
done