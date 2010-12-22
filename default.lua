-- this is the default callbacks file

--[[
This function is called in the very beginning.
Its argument is a random string generated by C code - to be used
for cookie encoding. If you are in a distributed environment, you may 
want to store this value. Likewise, if you are in a distributed
environment, maybe you want to persist your own random string.
This is why the first return value will set the random string
back in the C++ code.

]]

function initialize(random_secret)
  return random_secret
end

config = {
  sender_id = "82209006-86FF-4982-B5EA-D1E29E55D481",
  pub_spec = "tcp://127.0.0.1:8989",
  sub_spec = "tcp://127.0.0.1:8988",
}

function get_config_value(key)
  return config[key]
end

function p(str)
  print("LUA: " ..str)
end

function log_error(str)
  print("ERROR:" .. str)
end

assocs = {}

function store_assoc(op, handle, type, secret, expires_on)
  local ass = {
    op = op,
    handle = handle,
    type = type,
    secret = secret,
    expires_on = expires_on
  }
  p("Storing association for " .. op)
  assocs[#assocs+1] = ass
end

function find_assoc(server)
  local ass = nil

  p("Trying to find association for " ..server)
  for i,a in ipairs(assocs) do
    if a.op == server then
      ass = a
    end
  end

  if ass then
    return ass.op, ass.handle, ass.type, ass.secret, ass.expires_on
  else
    return nil
  end
end

function retrieve_assoc(server, handle)
  p("Trying to find association for " ..server .. " handle " .. handle)
  local ass = nil

  for i,a in ipairs(assocs) do
    if a.op == server and a.handle == handle then
      ass = a
    end
  end

  if ass then
    return ass.op, ass.handle, ass.type, ass.secret, ass.expires_on
  else
    return nil
  end

end

function invalidate_assoc(server, handle)
  local found = false
  p("Trying to invalidate association for " ..server .. " handle " .. handle)
end

-- Per-authentication attempt endpoint stuff

auths = {}

function begin_queueing(asnonce)
  p("Begin queueing for " .. asnonce)
  auths[asnonce] = {}
end

function queue_endpoint(asnonce, uri, claimed_id, local_id, expires_on)
  p("Enqueue for " .. asnonce .. " uri: " .. uri .. " claimed_id: " .. claimed_id ..
     " local_id: " .. local_id .. " expires_on: " .. tostring(expires_on))

  local ep = {
    uri = uri,
    claimed_id = claimed_id,
    local_id = local_id,
    expires_on = expires_on
  }
  table.insert(auths[asnonce], ep)
end

function next_endpoint(asnonce)
  p("Advancing to next endpoint for " .. asnonce)
  table.remove(auths[asnonce], 1)
end

function get_endpoint(asnonce)
  local ep = nil
  p("Getting endpoint for " .. asnonce)
  ep = auths[asnonce][1]
  if ep then
    p("Returning: " .. ep.uri .. ", " .. ep.claimed_id .. ", " .. ep.local_id)
    return ep.uri, ep.claimed_id, ep.local_id
  else
    return nil
  end
end

function set_normalized_id(asnonce, norm_id)
  p("Setting normalized id for " .. asnonce .. " to " .. norm_id)
end

function get_normalized_id(asnonce)
  local found = false
  p("Getting normalized id for " .. asnonce)
  if found then
    return "normalized_id"
  else
    return nil
  end
end

function check_nonce(server, nonce)
  local nonce_not_seen = true
  p("Checking nonce for server " .. server .. " nonce: " .. nonce)
  return nil
--[[
  if nonce_not_seen then
    return true
  else
    return nil
  end
]]
end

function auth_success(nonce, claimed_id)
  p("Authentication successful for " .. nonce .. " claimed id " .. claimed_id)
  --[[
    if this returns string, that string will be used as a value in a
    Set-Cookie header sent towards the client. If it returns nothing, 
    no attempts to set any cookies will be made.
    If you want to create some cookie and record its tie with the identity - 
    do it here and cook the correct header to have the cookie set on the client.
  ]]
end

profiles = {
  default = {
    active = "yes",
    handler_url = "http://beta.stdio.be:8888/openid",
    oncancel = "http://beta.stdio.be:8888/cancel.html",
  }
}

function get_profile_value(profile, key) 
  local prof = profiles[profile]
  if(prof) then
    return prof[key]
  else
    return nil
  end
end


p "We are using default.lua for callbacks"
