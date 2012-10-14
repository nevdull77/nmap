local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local testlib = require "testlib"
local vnc = require "vnc"

description = [[
Queries a VNC server for its protocol version and supported security types.
]]

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

---
-- @output
-- PORT    STATE SERVICE
-- 5900/tcp open  vnc
-- | vnc-info:  
-- |   Protocol version: 3.889
-- |   Security types:
-- |     Mac OS X security type (30)
-- |_    Mac OS X security type (35)
--

-- Version 0.2

-- Created 07/07/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 08/14/2010 - v0.2 - changed so that errors are reported even without debugging

Test = {

		new = function(self)
			local o = {
				inqueue = {
					"RFB 003.007\n"
				},
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
				if ( data:match("RFB 003.*") ) then
					table.insert(outqueue, bin.pack("H", "02 12 02"))
				end
			end
		end,

}


portrule = shortport.port_or_service( {5900, 5901, 5902} , "vnc", "tcp", "open")

action = function(host, port)

	if ( stdnse.get_script_args("test") ) then
		testlib.Test:new(Test)
	end

	local vnc = vnc.VNC:new( host.ip, port.number )
	local status, data
	local result = {}
	
	status, data = vnc:connect()
	if ( not(status) ) then	return "  \n  ERROR: " .. data end
	
	status, data = vnc:handshake()
	if ( not(status) ) then	return "  \n  ERROR: " .. data end

	status, data = vnc:getSecTypesAsStringTable()
	if ( not(status) ) then	return "  \n  ERROR: " .. data end

	table.insert(result, ("Protocol version: %s"):format(vnc:getProtocolVersion()) )

	if ( data and #data ~= 0 ) then
		data.name = "Security types:"
		table.insert( result, data )
	end
	
	if ( vnc:supportsSecType(vnc.sectypes.NONE) ) then
		table.insert(result, "WARNING: Server does not require authentication")
	end
	
	return stdnse.format_output(status, result)
end
