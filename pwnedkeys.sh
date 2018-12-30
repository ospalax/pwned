#!/bin/sh

#
# Copyright (2018) Petr Ospalý <petr@ospalax.cz>
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

set -e

CMD=$(basename "$0")
URL_API=https://v1.pwnedkeys.com
WORKING_DIR="${HOME}/tmp" # default, can be changed with -t|--temp

#
# functions
#

help()
{
    echo \
"
USAGE:
    ${CMD} [-h|--help|help]
        Print this help

    ${CMD} [-t|--temp <temp-dir>] <ssh-private-key.pem>
        Check if the key was pwned - argument is the path to the key

    This script will first export a pubkey from the provided private key. The
    exported pubkey must be in PKCS8/DER format from which the fingerprint
    is calculated. Such a fingerprint is then check via API.

    The whole procedure is described here:
    https://pwnedkeys.com/search.html

    I made this script because the description of the first step did not work
    for me - my SSH private key was in a newer openssh format. I switched to
    this newer format because the older one was vulnerable:
    https://latacora.micro.blog/2018/08/03/the-default-openssh.html

    Requirements:
        ssh-keygen
        openssl
        curl

    Optional:
        jq
"
}

on_exit()
{
    if [ "$DELETE_WORKING_DIR" = yes ] ; then
        echo "INFO: removing the working directory: ${WORKING_DIR}" >&2
        rm -rf "$WORKING_DIR"
    else
        # careful cleanup
        if [ -n "$SSH_PRIVATE_KEY_COPY" ] ; then
            if [ -f "$SSH_PRIVATE_KEY_COPY" ] \
                && [ "$SSH_PRIVATE_KEY_COPY" != "$SSH_PRIVATE_KEY_FILENAME" ] ;
            then
                echo "INFO: deleting the private key copy: $SSH_PRIVATE_KEY_COPY" >&2
                rm -f "$SSH_PRIVATE_KEY_COPY"
            fi
        fi
        if [ -n "$SSH_PUBKEY_FILENAME" ] ; then
            if [ -f "$SSH_PUBKEY_FILENAME" ] ; then
                echo "INFO: deleting the exported public key: $SSH_PUBKEY_FILENAME" >&2
                rm -f "$SSH_PUBKEY_FILENAME"
            fi
        fi
    fi

}

# arg: <curl response>
is_pwned()
{
    response="$@"

    # is response a json?
    if echo "$response" | grep -q '^[[:space:]]*[{].*[}][[:space:]]*$' ; then
        return 0
    fi

    return 1
}

# surround the text on the stdin with asterisks...
highlight_text()
{
    char="${1:-*}"
    awk -v character="$char" '
BEGIN {
    max=0;
    line_count=0;
}
{
    current_length=length($0);
    if (current_length > max)
        max = current_length;

    lines[++line_count]=$0;
    line_sizes[line_count]=current_length;
}
END {
    asterisk_line="";
    asterisk_count=max + 6; # six more spaces to compensate the padding
    for (i=1; i <= asterisk_count; i++)
    {
        asterisk_line=asterisk_line character;
    }
    empty_line=character;
    for (i=2; i <= asterisk_count-1; i++)
    {
        empty_line=empty_line " ";
    }
    empty_line=empty_line character;

    printf("%s\n", asterisk_line);
    printf("%s\n", empty_line);
    for (i=1; i <= line_count; i++)
    {
        diff_size=max - line_sizes[i];
        spaces="";
        for (k=1; k <= diff_size; k++)
            spaces=spaces " ";
        printf("%c  %s%s  %c\n", character, lines[i], spaces, character);
    }
    printf("%s\n", empty_line);
    printf("%s\n", asterisk_line);
}
'
}

# arg: PWNED|OK
print_status()
{
    case "$1" in
        PWNED)
cat <<EOF

########  ##  ##  ## ##    ##
##     ## ##  ##  ## ###   ##
##     ## ##  ##  ## ####  ##
########  ##  ##  ## ## ## ##
##        ##  ##  ## ##  ####
##        ##  ##  ## ##   ###
##         ###  ###  ##    ##

EOF
            ;;
        OK)
cat <<EOF

 #######  ##    ##
##     ## ##   ##
##     ## ##  ##
##     ## #####
##     ## ##  ##
##     ## ##   ##
 #######  ##    ##

EOF
            ;;
    esac
    printf "\nCHECK STATUS: ${1}\n\n"
}


#
# argument parsing
#

state=nil

while [ -n "$1" ] ; do
    case $state in
        nil)
            case "$1" in
                ''|-h|--help|help)
                    help
                    exit 0
                    ;;
                '--')
                    state=privkey
                    ;;
                -t|--temp)
                    state=temp
                    ;;
                *)
                    SSH_PRIVATE_KEY_FILENAME="$1"
                    state=done
                    ;;
            esac
            ;;
        privkey)
            SSH_PRIVATE_KEY_FILENAME="$1"
            state=done
            ;;
        temp)
            WORKING_DIR="$1"
            state=privkey
            ;;
        *)
            echo "ERROR: bad usage!" 2>&1
            help >&2
            exit 1
            ;;
    esac
    shift
done


#
# sanity checking
#

if [ -n "$SSH_PRIVATE_KEY_FILENAME" ] ; then
    if ! [ -f "$SSH_PRIVATE_KEY_FILENAME" ] ; then
        echo "ERROR: private key does not exist: ${SSH_PRIVATE_KEY_FILENAME}" 2>&1
        exit 1
    fi
else
    echo "ERROR: bad usage: private key is missing" 2>&1
    help >&2
    exit 1
fi

if ! which ssh-keygen >/dev/null ; then
    echo "ERROR: missing ssh-keygen" 2>&1
    exit 1
fi

if ! which openssl >/dev/null ; then
    echo "ERROR: missing openssl" 2>&1
    exit 1
fi

if ! which curl >/dev/null ; then
    echo "ERROR: missing curl" 2>&1
    exit 1
fi

if which jq >/dev/null 2>/dev/null ; then
    IS_JQ_INSTALLED=yes
fi

#
# start
#

# let us not forget to do some cleanup on the exit
trap on_exit INT TERM QUIT EXIT

# prepare working directory
DELETE_WORKING_DIR=no
WORKING_DIR=$(readlink -f "$WORKING_DIR")
if ! [ -d "$WORKING_DIR" ] ; then
    mkdir -p "$WORKING_DIR"
    DELETE_WORKING_DIR=yes
fi

# ssh-keygen should not alter the file but better safe than sorry...
SSH_PRIVATE_KEY_FILENAME=$(readlink -f "$SSH_PRIVATE_KEY_FILENAME")
SSH_PRIVATE_KEY_COPY="$WORKING_DIR"/$(basename "$SSH_PRIVATE_KEY_FILENAME")
if [ "$SSH_PRIVATE_KEY_COPY" != "$SSH_PRIVATE_KEY_FILENAME" ] ; then
    cp -pL "$SSH_PRIVATE_KEY_FILENAME" "$SSH_PRIVATE_KEY_COPY"
    chmod 600 "$SSH_PRIVATE_KEY_COPY"
fi

# now we can with peace of mind trying to export the pubkey
SSH_PUBKEY_FILENAME="${SSH_PRIVATE_KEY_COPY}.pub"
ssh-keygen -f "$SSH_PRIVATE_KEY_COPY" -e -m pkcs8 > "$SSH_PUBKEY_FILENAME"

echo "INFO: your public key in PKCS8/PEM format:"
cat "$SSH_PUBKEY_FILENAME" | highlight_text ' '
echo

# calculate the fingerprint
echo "INFO: calculating the fingerprint from the exported public key..."
FINGERPRINT=$(openssl rsa -pubin -in "$SSH_PUBKEY_FILENAME" -outform der \
    | openssl dgst -sha256 -hex \
    | sed -n 's/^[^[:space:]]\+[[:space:]]\+\([^[:space:]]\+\)$/\1/p')

# finally we can proceed to do the check
echo "INFO: checking the fingerprint via API:"
{
    echo "fingerprint:"
    echo "$FINGERPRINT"
    printf "\nURL:\n"
    echo "${URL_API}/${FINGERPRINT}"
} | highlight_text ' '
echo

RESPONSE=$(curl -L "${URL_API}/${FINGERPRINT}")
echo

# are we pwned?
if is_pwned "$RESPONSE" ; then
    printf '[!] ATTENTION: your ssh key has been pwned !!!\n' | highlight_text

    printf "\nINFO: reponse from API:\n\n"
    if [ "$IS_JQ_INSTALLED" = yes ] ; then
        echo "$RESPONSE" | jq .
    else
        echo "$RESPONSE"
    fi
    echo

    printf '[!] IMPORTANT: Revoke the SSH key and remove it from all of your .ssh/authorized_keys!\n' \
        | highlight_text

    print_status PWNED
    exit 2
else
    echo "OK: your SSH key seems to be safe (for now)" | highlight_text
    printf "\nINFO: reponse from API:\n"
    echo "$RESPONSE" | highlight_text ' '

    print_status OK
    exit 0
fi

exit 0
