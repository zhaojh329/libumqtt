#!/usr/bin/lua

local ev = require "ev"
local umqtt = require "umqtt"
local loop = ev.Loop.default

local auto_reconnect = true
local RECONNECT_INTERVAL = 5
local do_connect = nil

local function on_conack(c, sp, code)
	print(loop:now(), "Received conack:", sp, umqtt.return_code_string(code))
	c:publish("test", "I'm umqtt!", {qos = 1})
	c:subscribe(
		{topic = "test"},
		{topic = "test1", qos = 2}
	)
end

local function on_suback(c, granted_qos)
	io.write(loop:now(), " Received suback: ")

	for _, qos in ipairs(granted_qos) do
		io.write(qos, " ")
	end
	print("")
end

local function start_reconnect()
	if not auto_reconnect then
		loop:unloop()
		return
	end

	ev.Timer.new(function()
		do_connect()
	end, RECONNECT_INTERVAL):start(loop)
end

do_connect = function()
	local c = umqtt.connect({
		host = 'localhost',
		port = 1883,
		ssl = false,
		client_id = "umqtt-" .. os.time(),
		keep_alive = 30,
		username = "test",
		password = "123",
		clean_session = true,
		will = {
			topic = "test",
			message = "will msg",
			qos = 1,
			retain = true
		}
	})

	-- sp: session persistent
	-- code: return code
	c:on("conack", function(sp, code)
		on_conack(c, sp, code)
	end)

	c:on("suback", function(granted_qos)
		on_suback(c, granted_qos)
	end)

	c:on("unsuback", function()
		print(loop:now(), "Received unsuback")
	end)

	c:on("pingresp", function()
		print(loop:now(), "Received pingresp")
	end)

	c:on("publish", function(topic, payload)
		print(loop:now(), "Received publish:", topic, payload)
	end)

	c:on("close", function()
		print(loop:now(), "Closed by peer")
		start_reconnect()
	end)

	c:on("error", function(err, msg)
		print(loop:now(), "Error occurred:", err, msg)
		start_reconnect()
	end)
end

ev.Signal.new(function()
	loop:unloop()
end, ev.SIGINT):start(loop)

do_connect()

-- major minor patch
local version = string.format("%d.%d.%d",  umqtt.version())
print(loop:now(), "Version:", version)

loop:loop()

print(loop:now(), "Normal quit")