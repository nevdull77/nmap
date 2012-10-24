local stdnse = require("stdnse")
local nmap = require("nmap")
_ENV = stdnse.module("testlib", stdnse.seeall)

local TestSocket = {
	
	new = function(self, testclass)
		local o = {
			testclass = testclass,
			test_recv = testclass:next_recv(),
			test_send = testclass:next_send(),
			inbuf = "",
		}
		setmetatable(o, self)
		self.__index = self
		return o
	end,
	
	connect = function(self, host, port)
		self.host, self.port = host, port
		self.testclass.host = host
		self.testclass.port = port
		return true
	end,
	
	receive = function(self)
		return self:receive_bytes()
	end,
	
	receive_buf = function(self, delimiter, keeppattern)
		local status, data = self:receive_bytes()
		if ( not(status) ) then
			return false, "EOF"
		end
		self.inbuf = self.inbuf .. data
		
		local func = ( "string" == type(delimiter) ) and string.match or delimiter
		local start, stop = func(self.inbuf)
		local tmp = self.inbuf:sub(1, start)
		if ( keeppattern and stop - start > 0 ) then
			tmp = tmp .. self.inbuf:sub(start, stop)
		end
		
		self.inbuf = self.inbuf:sub(stop + 1)
		return status, tmp
	end,
	
	receive_bytes = function(self, num)
		self.inbuf = self.inbuf .. ( self.test_recv() or "" )
		local chunk = ( num and tonumber(num) > 1 ) and self.inbuf:sub(1, num) or self.inbuf
		if ( #chunk ~= #self.inbuf ) then
			self.inbuf = self.inbuf(num + 1)
		elseif ( #chunk == 0 ) then
			return false, "EOF"
		else
			self.inbuf = ""
		end
		stdnse.print_debug(3, "TestSocket Receiving: %s", chunk)
		return true, chunk
	end,
		
	set_timeout = function(self) return true end,
	
	send = function(self, data) 
		self.test_send(data)
		return true
	end,
	
	close = function(self) return true end,
	
}

Test = {
	
	new = function(self, class)
		local o = {	}
		setmetatable(o, self)
		self.__index = self
		nmap.new_socket = function()
			local tc = class:new()
			tc.testcase = stdnse.get_script_args("test.case")
			return TestSocket:new(tc)
		end
		return o
	end,	
}

return _ENV;