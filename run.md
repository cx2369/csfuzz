```
jq '. @@'
nm-new '-a -C -l --synthetic @@'
tcpdump '-evnnnr @@'
objdump '-S @@'
imginfo '-f @@'
wav2swf '-o /dev/null @@'
lame '@@ /dev/null'
sqlite3 ''

asn1 '@@'
lua '@@'
pdftopdm '-mono -cropbox @@'
sndfile_fuzzer '@@'
sqlite3_fuzz '@@'
tiff_read_rgba_fuzzer '@@'
xmllint '--valid --oldxml10 --push --memory @@'
```
