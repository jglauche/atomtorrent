#! /usr/bin/python
#
# FILE
#	atomstore.py	-- Low-level atom storage and HTTP API for AtomTorrent
#
# DESCRIPTION
#	AtomTorrent is the RepRap community's Distributed Storage Service.
#
#	atomstore.py implements a prototype of the HTTP API and simple file-based
#	storage for AtomTorrent, using SHA-512 hash digests as universal atom addresses.
#
#	THIS IS A PROTOTYPE, created for exploring the concept.  You've been warned.
#
# CURRENT FUNCTIONALITY
#	- Atoms can be stored with HTTP POST and fetched back with HTTP GET.
#	- Atoms are stored using the base64 encoding of the full SHA-512 hash.
#	- Adopted the "modified Base64 for filenames" standard variant of base64
#	  because otherwise it is impossible to extract the Atom-ID from URIs.
#	- Stored atoms are also hard-linked to the SHA-512/120 truncated hash.
#	- Clients are handed back the shorter SHA-512/120 address by default
#	  because collisions will be very rare so the full hash can be left
#	  to special collision exception handling.
#	- Clients can choose atom-IDs to be returned in hex or base64 encoding.
#
# TODO
#	- There is no validation of atom-ID lengths sent in client GETs yet.
#	- GET using hex atom-ID is treated as base64, needs HTTP header to distinguish types.
#	- There is no metadata handling yet.
#	- There is no metatype handling yet.
#	- There is no private/public key handling yet.
#	- The URL to which POSTs are written is not used or checked.
#	- The '=' characters in some base64 filenames need figuring out, bug or OK?
#	- There is no collision testing yet, although the framework for it is there.
#	- Not yet distinguishing 201 on initial create from 200 for re-store/already-exists.
#	- Add a "hash atom but don't store it" option so clients can just ask for the address.
#	- The return format and choice of returned data needs to be given more thought.
#	- It needs a configuration file for options to replace the hardwired config section.
#	- It needs commandline handling, to choose a config file and enable debug etc.
#	- It needs logging.
#	- It needs stats.
#	- It needs tests [I'm writing some - Morg].
#
# REFERENCES
#	1. FIPS PUB 180-3, Secure Hash Standard (SHS), 2008.
#	2. NIST Special Publication 800-107, Recommendation for Applications Using Approved Hash Algorithms, 2009.
#
# AUTHORS
#	Morgaine Dinova <morgaine.dinova@googlemail.com>
#	... more peeps hopefully
#
# DOCUMENTATION
#	For now, see http://titanpad.com/0dhWwj5x5p (W.I.P.)
#
# BUGS
#	- When a GET request fails and the client like "curl --fail" terminates the session uncleanly,
#	  the BaseHTTPRequestHandler class library prints a traceback instead of raising an exception
#	  when it finds the socket closed.  Although it recovers, it makes our stdout log look awful.
#
# LICENSE
#	AGPLv3 or later
#

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from os import sep
import re
import base64
import hashlib
import os
import string

# We'll need a config file to set up paths and other parameters.  Hardwiring it for now.
# =======================================
#                CONFIG
# =======================================
server_host		= '0.0.0.0'	# IP address or hostname: the listener binds to this
port_number		= 5080		# TCP port number or svc name: listener binds to this
atomstore_path		= "store"	# Parent directory for the tree of storage directories
directory_depth		= 4		# Depth of access tree, eg. 4 gives store/1/2/3/4/file
default_return_base64	= True		# Use base64 as default Atom-ID encoding, else use hex
verbose			= False		# Generate verbose diagnostic output, else be quiet
veryverbose		= False		# Generate even more verbose output, else don't
# =======================================

# Make a translation table for mapping base64's '/' characters out of filenames
trn_tab = string.maketrans('/', '-')

# Given an atom_id string such as "deadbeef", for a depth of 4 returns "d/e/a/d/"
def gen_directory_nodes(atom_id):
    # List comprehension followed by a join is the fastest way of doing this in Python
    return ''.join([atom_id[position]+'/' for position in range(directory_depth)])

# Hex and base64 validators.
# Note that the atomstore doesn't care whether hex or base64 is used, it will always convert
# whatever is supplied into its own preferred storage format, which is likely to be base64 to
# keep names shorter when using plain files as storage.  However, it needs to be told which
# is being used since hex is a subset of base64 and so they are not always distinguishable.

def valid_hex(atom_id):
    # Using regex here only for brevity in the prototype.  Do it properly with arrays for production.
    if re.search('[^0-9a-fA-F]', atom_id):
        return 0
    return 1

def valid_base64(atom_id):	# NB. Validates for "Modified Base64 for filenames", ie. #64 = '-'
    # Using regex here only for brevity in the prototype.  Do it properly with arrays for production.
    if re.search('[^0-9a-zA-Z+-]', atom_id):
        # NOTE: We cannot use the 64th character of base64 '/' if we're going to store data
        # using the atom-ID as filename directly, since '/' is the Unix directory separator.
        # Fortunately replacing '/' by '-' is a widespread modification of the original base64.
        return 0
    return 1

#
# Computes the SHA-512 hash of the POSTed atom data, encodes it into base64, translates the base64
# into the standard "modified Base64 for filenames" variant, and stores the atom using this modified
# base64 encoding as the filename.  A name made of the leading 20 characters is also linked to this
# stored atom, which represents SHA-512/120 (128 is not evenly divisible by the 6 bits of base64).
#
# 120 bits was chosen because it is exactly divisible by 4, 6 and 8, and therefore avoids all padding
# issues in hex, base64, and octets.  And, being less than 128 bits, it will fit within 4-word fields
# intended to carry UUIDs and IPv6 addresses, which will be less problematic than 144 bits.
#
# The code is rather inefficient because were're scanning the atom data once to compute the SHA-512 hash
# and once again to write the atom to filestore.  The production version should try to avoid a rescan.
#
# Atom-ID lengths:
#	Hash/truncation		bits	binary-octets		hex-chars	base64-chars	exact
#	---------------		----	-------------		---------	------------	-----
#	SHA-512			512		64		128		85 + 2 bits	-
#	SHA-512/144		144		18		36		24		yes
#	SHA-512/132		132		16 + 4 bits	33		22		-
#	SHA-512/128		128		16		32		21 + 2 bits	-
#	SHA-512/120		120		15		30		20		yes
#
def hash_and_store(post_data, return_base64):
    # HASHING
    hash512 = hashlib.sha512(post_data)
    sha_512 = hash512.digest()				# This is the actual binary SHA-512 hash digest

    hex_hash512 = hash512.hexdigest()			# Hex encoding of SHA-512 hash digest
    hex_hash120 = hex_hash512[0:29]			# Leading 30 hex characters for SHA-512/120

    # Generate base64 as the universal atom address, although it can't be used directly
    b64_hash512 = base64.b64encode( sha_512 )

    # Translate into "Modified Base64 for filenames", a well-known variant of base64
    x64_hash512 = string.translate(b64_hash512,trn_tab)	# This translates all '/' into '-'
    x64_hash120 = x64_hash512[0:19]			# Leading 20 base64 characters for SHA-512/120

    if verbose and (x64_hash512 != b64_hash512):
        print "Base64 translation triggered for Atom-ID {%s}" % b64_hash512	# Just informational

    #
    # STORAGE
    # Note that we need the base64 encoding for our filenames, even if the client only wants hex.
    #
    directory_nodes = gen_directory_nodes(x64_hash512)
    if verbose: print "Generated directory tree {%s}" % directory_nodes

    # Now make the directories with os.makedirs(), which is similar to `mkdir -p`
    dir_path = atomstore_path + sep + directory_nodes
    try:
        if not os.path.exists(dir_path):
            if verbose: print "Creating directory tree {%s}" % dir_path
            os.makedirs(dir_path)
    except:
        print "Failed to create directory tree {%s}" % dir_path
        return ""

    # And then write the atom to filestore in the inner directory with the base64 hash as filename
    write_filepath = dir_path + x64_hash512
    link120_path = dir_path + x64_hash120
    if verbose: print "Atom file path is {%s}" % write_filepath
    try:
        if not os.path.exists(write_filepath):
            if verbose: print "Writing atom file {%s}" % write_filepath
            outfp = open(write_filepath, 'w')
            outfp.write(post_data)
            outfp.close()
    except:
        print "Failed to write atom file {%s}" % write_filepath
        return ""

    # Finally, create a hard link with the 120-bit truncation of SHA-512 pointing at the full hash.
    # (Should we use a symlink instead?  What are the tradeoffs?)
    link120_path = dir_path + x64_hash120
    if verbose: print "Link120 file path is {%s}" % link120_path
    try:
        # No collision detection yet, so we're simply assuming that link presence means that this
        # same atom is already stored, not admitting that the link might be to a different atom.
        if not os.path.exists(link120_path):
            if verbose: print "Linking atom file {%s}" % link120_path
            os.link(write_filepath, link120_path)
    except:
        print "Failed to link {%s} to {%s}" % (link120_path, write_filepath)
        # Force use of the full SHA-512 hash when failed to create the 120-bit link
        if return_base64:
            return x64_hash512
        else:
            return hex_hash512

    # We're not detecting collisions yet so just return 120-bit and pretend collisions can't happen
    if return_base64:
        return x64_hash120
    else:
        return hex_hash120

#
# Bog standard use of BaseHTTPRequestHandler here, nothing really worth explaining.
#
# We implement only GET and POST to give us the eclectic immutable subset of REST.
# Notice that we're sorta "beyond idempotent" by storing immutable atoms with POST.
# We're even idempotent across POSTs by separate clients. (Well, kind of.)
# Somebody needs to write a paper about post-idempotent immutable REST. :P
#
# IMPORTANT: it's worth considering dropping BaseHTTPServer altogether.  It's mainly
# targetted at making webservers for websites and not WEB SERVICES (big difference),
# and so it's generating HTTP and other crap which we don't need since a web browser
# is never going to see our output, except by mistake or for testing.
#
class AtomStore(BaseHTTPRequestHandler):

    def do_GET(self):
        atom_id = self.path
        if verbose:
            print "==========================================="
            print "Received GET %s from client %s" % (atom_id, self.client_address)

        try:
            # First of all, extract the atom-ID from the URL prefix.
            dir_prefix = os.path.dirname(atom_id)
            atom_id = os.path.basename(atom_id)
            if verbose:
                print "Atom-ID extracted from path in URI: {%s} + {%s}" % (dir_prefix, atom_id)

            # Once we have a client header to tell the server whether the client's atom-ID is hex
            # or base64, we'll be able to do some proper validation here.  It's very poor ATM.
            if not (valid_hex(atom_id) or valid_base64(atom_id)):
                self.send_error(400, 'Invalid Atom-ID Syntax: %s' % atom_id)               
                return

            if veryverbose:
                print 'Headers={\n%s}' % self.headers
            user_header = self.headers.getheader('User-agent')
            host_header = self.headers.getheader('Host')
            accept_header = self.headers.getheader('Accept')
            length_header = self.headers.getheader('Content-length')
            ctype_header = self.headers.getheader('Content-type')
            acenc_header = self.headers.getheader('Accept-encoding')

            directory_nodes = gen_directory_nodes(atom_id)
            atom_path = atomstore_path + sep + directory_nodes + atom_id
            if verbose:
                print "Looking up atom path {%s}" % atom_path

            #=========================
            try:
                atom = open(atom_path)
            except:
                try:
                    self.send_error(404, 'Atom Not Found: %s' % atom_id)
                    return
                except Exception, e:
                    print "An unexpected exception was encountered: %s" % str(e)
                    print "STUPID CLASS LIBRARY displays a traceback when it tries to write to a closed client socket"
                    #
                    # It's "curl -s --fail URL" that closes the socket badly on failure, but the library should handle it anyway.
                    # How do I stop the unwanted traceback?
                    #
                    return
                except:
                    print "CANNOT HAPPEN"
                    return
            #=========================

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()					# End of RESPONSE headers
            file_data = atom.read()
            if acenc_header == 'base64':
                self.wfile.write( base64.b64encode(file_data) )	# decode with base64.b64decode()
            else:
                self.wfile.write( file_data )
            atom.close()
            return

        except:
            self.send_error(500, 'Exception - Internal Error GET-1')
            return


    def do_POST(self):
        post_target = self.path
        if verbose:
            print "==========================================="
            print "Received POST %s from client %s" % (post_target, self.client_address)

        # return 201 if new atom created, 200 if it's an idempotent "store same thing"
        try:
            if veryverbose:
                print 'Headers={\n%s}' % self.headers
            user_header = self.headers.getheader('User-agent')
            host_header = self.headers.getheader('Host')
            acenc_header = self.headers.getheader('Accept-encoding')
            accept_header = self.headers.getheader('Accept')
            length_header = self.headers.getheader('Content-length')
            ctype_header = self.headers.getheader('Content-type')

            post_length = int(length_header)

            if verbose:
                print 'user_header={%s}' % user_header
                print 'host_header={%s}' % host_header
                print 'acenc_header={%s}' % acenc_header
                print 'accept_header={%s}' % accept_header
                print 'length_header={%s}' % length_header
                print 'ctype_header={%s}' % ctype_header

            if ctype_header == 'multipart/form-data':
                self.send_error(400, 'Multipart Not Implemented')
                return

            # Whether hex or base64 encoding is returned to the client by POST can be
            # chosen by including "hex" or "base64" in the 'Accept-encoding' header.
            # If the client makes no choice then the default config setting is used.
            return_base64 = default_return_base64
            try:
                if re.search(r'\bhex\b', acenc_header):
                    return_base64 = False
                if re.search(r'\bbase64\b', acenc_header):	# If both present, base64 overrides
                    return_base64 = True
            except:
                pass
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
 
            post_data = self.rfile.read(post_length)
            if verbose: print 'Data[%d]={%s}' % (post_length, post_data.rstrip('\n\r'))

            # Store the atom indexed by its SHA-512 hash
            new_atom_id = hash_and_store(post_data, return_base64)
            if new_atom_id == "":
                response = "POST Status=WRITE_FAIL Length=%d\n" % post_length
            else:
                response = "POST Status=OK Length=%d Atom-ID=%s\n" % (post_length, new_atom_id)

            if verbose: print "Response: {%s}" % response.rstrip('\n\r')

            self.end_headers()					# End of RESPONSE headers

            # Hand the client back a response containing the atom-ID of the stored atom.
            # The return format needs much more careful thought.  Even though we're not
            # implementing a webserver to run HTML websites, we may need some compatibility
            # with frameworks to help them integrate with our back-end storage system.
            self.wfile.write(response)
            return
            
        except:
            self.send_error(500, 'Exception - Internal Error POST-1')
            return

def main():
    try:
        server = HTTPServer((server_host, port_number), AtomStore)
        print 'AtomStore server listening on %s:%d' % (server_host, port_number)
        server.serve_forever()
    except KeyboardInterrupt:
        print 'AtomStore server aborting'
        server.socket.close()
    except:
        print 'AtomStore FAILED to start listener on %s:%d' % (server_host, port_number)

if __name__ == '__main__':
    main()

