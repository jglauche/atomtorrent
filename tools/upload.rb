#!/usr/bin/ruby
#
# FILE
#       upload.rb    -- a very simple file uploader (for testing purposes)
#
# AUTHORS
#	Joachim Glauche <webmaster@joaz.de>
#
# LICENSE
#       AGPLv3 or later
#


require "rubygems"
begin
	require "rest-client"
rescue
	puts "Please install rest-client (gem install rest-client)"
end

if ARGV[0] == nil 
   puts "Usage: ruby upload.rb filename"
   exit
else
   content = File.read(ARGV[0])
end



# hardcoded config stuff
url = "http://localhost:5080"

result = RestClient.post url, content





