-- this is the default callbacks file

--[[
This function is called in the very beginning.
Its argument is a random string generated by C code - to be used
for cookie encoding. If you are in a distributed environment, you may 
want to store this value. Likewise, if you are in a distributed
environment, maybe you want to persist your own random string.
This is why the first return value will set the random string
back in the C++ code.

The next return arguments define the sender_id, and 
the 0mq specifications for connecting to mongrel2
]]

function initialize(random_secret)
  local sender_id = "82209006-86FF-4982-B5EA-D1E29E55D481"
  local zmq_pub_spec = "tcp://127.0.0.1:8989"
  local zmq_sub_spec = "tcp://127.0.0.1:8988"
  return random_secret, sender_id, zmq_pub_spec, zmq_sub_spec
end

print "We are using default.lua for callbacks"