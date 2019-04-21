#!/usr/bin/lua

local ev = require "ev"
local umqtt = require "umqtt"
local loop = ev.Loop.default

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
	print(loop:now(), "Received conack:", sp, umqtt.return_code_string(code))
	c:publish("test", "I'm umqtt!", {qos = 1})
	c:subscribe(
		{topic = "test"},
		{topic = "test1", qos = 2}
	)
end)

c:on("suback", function(granted_qos)
	io.write(loop:now(), " Received suback: ")

	for _, qos in ipairs(granted_qos) do
		io.write(qos, " ")
	end
	print("")
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
	loop:unloop()
end)

c:on("error", function(err, msg)
	print(loop:now(), "Error occurred:", err, msg)
	loop:unloop()
end)

ev.Signal.new(function()
	c:unsubscribe("test", "test1")

	ev.Timer.new(function()
		loop:unloop()
	end, 1):start(loop)
end, ev.SIGINT):start(loop)

-- major minor patch
local version = string.format("%d.%d.%d",  umqtt.version())
print(loop:now(), "Version:", version)

loop:loop()

print(loop:now(), "Normal quit")