local dns = require "dns"
local http = require "http"
local ipOps = require "ipOps"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local url = require "url"
local testlib = require "testlib"

description = [[
Shows the title of the default page of a web server.

The script will follow no more than one HTTP redirect, and only if the
redirection leads to the same host. The script may send a DNS query to
determine whether the host the redirect leads to has the same IP address as the
original target.
]]

---
--@output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-title: Go ahead and ScanMe!
--
-- @xmloutput
-- <elem key="title">Go ahead and ScanMe!</elem>
-- @xmloutput
-- <elem key="title">Wikipedia, the free encyclopedia</elem>
-- <elem key="redirect_url">http://en.wikipedia.org/wiki/Main_Page</elem>

author = "Diman Todorov"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

Test = {
	
	new = function(self)
		local o = {
			inqueue = {},
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	next_recv = function(self)
		inqueue = self.inqueue
		return function()
			return table.remove(inqueue, 1)
		end
	end,
	
	next_send = function(self)
		local outqueue = self.inqueue
		return function(data)
			if ( data:match("GET / HTTP") ) then
				local testcase = tonumber(self.testcase)
				if ( testcase == 1 ) then
					table.insert(outqueue, [[HTTP/1.1 200 OK
Date: Sat, 13 Oct 2012 19:02:41 GMT
Expires: -1
Cache-Control: private, max-age=0
Content-Type: text/html; charset=UTF-8
Connection: close

<html>
<body>
<title>Test</TiTle>
</body>
</html>
]])
				elseif( testcase == 2 ) then
					table.insert(outqueue, ([[HTTP/1.1 301 Moved Permanently
Location: http://%s/
Content-Type: text/html
Content-Length: 174

<html>
<head>
<title>Moved</title>
</head>
<body>
<h1>Moved</h1>
<p>This page has moved to <a href="http://%s/">http://%s/</a>.</p>
</body>
</html>
]]):format(self.host.ip, self.host.ip, self.host.ip))
				else
					table.insert(outqueue, "HTTP/1.1 404 Not Found\n\n")
				end

			end
		end
	end,
	
}

action = function(host, port)

	if ( stdnse.get_script_args("test") ) then
		testlib.Test:new(Test)
	end

  local resp, redirect_url, title

  resp = http.get( host, port, '/' )

  -- check for a redirect
  if resp.location then
    redirect_url = resp.location[#resp.location]
    if resp.status and tostring( resp.status ):match( "30%d" ) then
      return {redirect_url = redirect_url}, ("Did not follow redirect to %s"):format( redirect_url )
    end
  end

  if ( not(resp.body) ) then
    return
  end

  -- try and match title tags
  title = string.match(resp.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")

  local display_title = title

  if display_title and display_title ~= "" then
    display_title = string.gsub(display_title , "[\n\r\t]", "")
    if #display_title > 65 then
      display_title = string.sub(display_title, 1, 62) .. "..."
    end
  else
    display_title = "Site doesn't have a title"
    if ( resp.header and resp.header["content-type"] ) then
      display_title = display_title .. (" (%s)."):format( resp.header["content-type"] )
    else
      display_title = display_title .. "."
    end
  end

  local output_tab = stdnse.output_table()
  output_tab.title = title
  output_tab.redirect_url = redirect_url

  local output_str = display_title
  if redirect_url then
    output_str = output_str .. "\n" .. ("Requested resource was %s"):format( redirect_url )
  end

  return output_tab, output_str
end
