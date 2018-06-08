require "uloop"

local umqtt = require('umqtt')

uloop.init()

local c = umqtt.connect({
	host = 'localhost',
	port = 1883,
	client_id = 'kingbanik',
	password = '123',
	username = 'meh',
	clean_session = true,
	will = {
		topic = 'test4',
		payload = 'going home, bye!',
		qos = 2
	},
	ping_interval = 5,
	-- reconnect_interval = 0,
})

print(c)
print("is_connected", c:is_connected())

c:on_connection(function(session_persistent, return_code)
	print('on_connection', session_persistent, c:return_code_string(return_code))
	assert(return_code == umqtt.CONNECTION_ACCEPTED)

	c:publish({ topic="test3", qos=1, payload='oh my ladies!'})

	if not session_persistent then
		print('subscribing...')
		c:subscribe({
			{ topic='test1' },
			{ topic='test2', qos=1 },
			{ topic='test3', qos=2 },
		})
	end
end)

c:on_subscribe(function(mid, ...)
	local t = {...}
	print('on_subscribe', mid, #t, t[1], t[2], t[3])
	c:publish({ topic="test3", qos=1, payload='yay!'})
end)

c:on_publish(function(msg)
	table.foreach(msg, print)
end)

c:on_pong(function()
	print("on_pong")
	c:publish({ topic="test3", qos=1, payload='pong!'})
end)

c:on_error(function(error_code)
	print("on_error", c:error_code_string(error_code))
end)

c:on_close(function(auto_reconnect)
	print("on_close")

	if not auto_reconnect then
		print("should reconnect manualy here")
	else
		print("reconnecting in progress...")
	end
end)

local reconnect_count = 0
c:on_reconnect(function()
	reconnect_count = reconnect_count + 1
	print("on_reconnect", reconnect_count)
	if reconnect_count > 9 then
		uloop.cancel()
	end
end)

-- c:disconnect()
uloop.run()
