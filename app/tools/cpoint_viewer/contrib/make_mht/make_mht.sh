#!/bin/sh

BOUNDARY="XxXxXx--BOUNDARY--xXxXxX"

PWD="`pwd`"
IMAGES=`lynx -dump -image_links $1 | grep file:// | grep -v "$1" | sed 's#^.*icons/#icons/#' | sort -u`

echo 'From: <Saved by Microsoft Internet Explorer 5>'
echo 'Subject: Firewall Policy'
echo "Date: `date`"
echo 'MIME-Version: 1.0'
echo 'Content-Type: multipart/related;'
echo '	boundary="'${BOUNDARY}'";'
echo '	type="text/html"'
echo ''
echo 'This is a multi-part message in MIME format.'
echo ''
echo "--${BOUNDARY}"
echo 'Content-Type: text/html'
echo 'Content-Transfer-Encoding: base64'
echo 'Content-Location: file://'$1
echo ''
/usr/local/bin/base64_encode $1
echo ""

for IMG in $IMAGES ; do
  echo "--${BOUNDARY}"
  echo "Content-Type: image/png"
  echo "Content-Transfer-Encoding: base64"
  echo "Content-Location: file:///${IMG}"
  echo ""
  /usr/local/bin/base64_encode $IMG
  echo ""
done


echo "--${BOUNDARY}--"

