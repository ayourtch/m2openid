#include <zmq.hpp>
#include <cstring>
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include "m2pp.hpp"
/* other general lib includes */
#include <curl/curl.h>
#include <pcre.h>
#include <sqlite3.h>

#include <ctime>
#include <cstdlib>

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace std;

/* opkele includes */
#include <opkele/exception.h>
#include <opkele/types.h>
#include <opkele/util.h>
#include <opkele/association.h>
#include <opkele/prequeue_rp.h>
#include <opkele/sreg.h>

using namespace opkele;
extern "C" {
#include "lua5.1/lua.h"
#include "lua5.1/lualib.h"
#include "lua5.1/lauxlib.h"
}


#include "sha1.h"

lua_State *L;

void lua_report_error(lua_State *L) {
  cout << lua_tostring(L, -1);
  cout << "\n";
  lua_pop(L, 1);
}

int lua_find_func(lua_State *L, string func_name) {
  lua_getglobal(L, func_name.c_str());
  if(!lua_isfunction(L,-1)) {
    lua_pop(L,1);
    return 0;
  } else {
    return -1;
  }
}

int lua_call_func(lua_State *L, int nargs, int nres) {
  if (lua_pcall(L, nargs, nres, 0) == 0) {
    return -1; 
  } else {
    lua_report_error(L);
    return 0; 
  }
}

namespace m2openid {
  using namespace std;

  // Wrapper for basic_openid_message - just so it works with openid namespace
  class m2openid_message_t : public params_t {
  public:
    m2openid_message_t(params_t& _bom) { bom = _bom; };
    bool has_field(const string& n) const { return bom.has_param("openid."+n); };
    const string& get_field(const string& n) const { return bom.get_param("openid."+n); };
    bool has_ns(const string& uri) const { return bom.has_ns(uri); };
    string get_ns(const string& uri) const { return bom.get_ns(uri); };
    fields_iterator fields_begin() const { return bom.fields_begin(); };
    fields_iterator fields_end() const { return bom.fields_end(); };
    void reset_fields() { bom.reset_fields(); };
    void set_field(const string& n,const string& v) { bom.set_field(n, v); };
    void reset_field(const string& n) { bom.reset_field(n); };

  private:
    params_t bom;
  };


  uint64_t timenow() {
    struct timeval tv;
    uint64_t time_now;
    gettimeofday(&tv, NULL);
    time_now = (((uint64_t) 1000000) * (uint64_t) tv.tv_sec +
          (uint64_t) tv.tv_usec);  
    return time_now;
  }

  int true_random() {
    uint64_t time_now = timenow();
    srand((unsigned int)(((time_now >> 32) ^ time_now) & 0xffffffff));
    return rand() & 0x0FFFF;
  };

  void make_rstring(int size, string& s) {
    s = "";
    const char *cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for(int index=0; index<size; index++)
      s += cs[true_random()%62];
  }


  vector<string> explode(string s, string e) {
    vector<string> ret;
    int iPos = s.find(e, 0);
    int iPit = e.length();
    while(iPos>-1) {
      if(iPos!=0)
        ret.push_back(s.substr(0,iPos));
      s.erase(0,iPos+iPit);
      iPos = s.find(e, 0);
    }
    if(s!="")
      ret.push_back(s);
    return ret;
  };

  string url_decode(const string& str) {
    char * t = curl_unescape(str.c_str(),str.length());
    if(!t)
      throw; // failed_conversion(OPKELE_CP_ "failed to curl_unescape()");
    string rv(t);
    curl_free(t);
    return rv;
  };

  opkele::params_t parse_query_string(const string& str) {
    opkele::params_t p;
    if(str.size() == 0) return p;

    vector<string> pairs = explode(str, "&");
    for(unsigned int i=0; i < pairs.size(); i++) {
      string::size_type loc = pairs[i].find( "=", 0 );
      // if loc found and loc isn't last char in string
      if( loc != string::npos && loc != str.size()-1) {
        string key = url_decode(pairs[i].substr(0, loc));
        string value = url_decode(pairs[i].substr(loc+1));
        p[key] = value;
      }
    }
    return p;
  };

};

opkele::params_t parsereq(m2pp::request req) {
  opkele::params_t h;
  std::ostringstream response;
  response << "<pre>" << std::endl;
  response << "SENDER: " << req.sender << std::endl;
  response << "IDENT: " << req.conn_id << std::endl;
  response << "PATH: " << req.path << std::endl;
  response << "BODY: " << req.body << std::endl;
  for (std::vector<m2pp::header>::iterator it=req.headers.begin();it!=req.headers.end();it++) {
    response << "HEADER: " << it->first << ": " << it->second << std::endl;
    h[it->first] = it->second; 
  }
  response << "</pre>" << std::endl;

  // std::cout << response.str();
  return h;
}

string dumpreq(m2pp::request req) {
  std::ostringstream response;
  response << "<pre>" << std::endl;
  response << "SENDER: " << req.sender << std::endl;
  response << "IDENT: " << req.conn_id << std::endl;
  response << "PATH: " << req.path << std::endl;
  response << "BODY: " << req.body << std::endl;
  for (std::vector<m2pp::header>::iterator it=req.headers.begin();it!=req.headers.end();it++) {
    response << "HEADER: " << it->first << ": " << it->second << std::endl;
  }
  response << "</pre>" << std::endl;

  return response.str();
}


map<string, opkele::assoc_t> all_associations;


class m2_rp_t : public opkele::prequeue_RP {
  public:
    long as_id;
    string asnonceid;
    string serverurl;

  m2_rp_t(const string& _asnonceid, const string& _serverurl): as_id(0), asnonceid(_asnonceid), serverurl(_serverurl) {
  }

  /* Global persistent store */

  opkele::assoc_t ass;
  int have_ass;

  opkele::assoc_t store_assoc(
                const string& OP,const string& handle,
                const string& type,const opkele::secret_t& secret,
                int expires_in) {
    time_t rawtime;
    time (&rawtime);
    int expires_on = rawtime + expires_in;

    if(lua_find_func(L, "store_assoc")) {
      lua_pushstring(L, OP.c_str());
      lua_pushstring(L, handle.c_str());
      lua_pushstring(L, type.c_str());
      lua_pushstring(L, util::encode_base64(&(secret.front()),secret.size()).c_str());
      lua_pushnumber(L, expires_on);
      if(lua_call_func(L, 5, 0)) {
      } else {
        // FIXME - is this a correct exception ?
        throw opkele::failed_lookup(OPKELE_CP_ "Could not store!");
      };
    } else {
      // FIXME - is this a correct exception ?
      throw opkele::failed_lookup(OPKELE_CP_ "Could not store!");
    }

    ass = opkele::assoc_t(new opkele::association(
                        OP, handle, type, secret, expires_on, false ));
    return ass;
   
  }

  opkele::assoc_t find_assoc(
                const string& OP) {

    if(lua_find_func(L, "find_assoc")) {
      lua_pushstring(L, OP.c_str());
      if(lua_call_func(L, 1, 5)) {
        if(!lua_isnil(L, -5)) {
          string server = luaL_checkstring(L, -5);
          string handle = luaL_checkstring(L, -4);
          string type = luaL_checkstring(L, -3);
          string secret_s = luaL_checkstring(L, -2);
          int expires_on = luaL_checknumber(L, -1);
          secret_t secret;
          util::decode_base64(secret_s, secret);
          assoc_t result = assoc_t(new association(server, handle, type, secret, expires_on, false));
          return result;
        }
      }
    }
    throw opkele::failed_lookup(OPKELE_CP_ "Couldn't find unexpired handle");
  }

  opkele::assoc_t retrieve_assoc(
                const string& OP,const string& handle) {
    if(lua_find_func(L, "retrieve_assoc")) {
      lua_pushstring(L, OP.c_str());
      lua_pushstring(L, handle.c_str());
      if(lua_call_func(L, 2, 5)) {
        if(!lua_isnil(L, -5)) {
          string server = luaL_checkstring(L, -5);
          string handle = luaL_checkstring(L, -4);
          string type = luaL_checkstring(L, -3);
          string secret_s = luaL_checkstring(L, -2);
          int expires_on = luaL_checknumber(L, -1);
          secret_t secret;
          util::decode_base64(secret_s, secret);
          assoc_t result = assoc_t(new association(server, handle, type, secret, expires_on, false));
          return result;
        }
      }
    }
    throw opkele::failed_lookup(OPKELE_CP_ "Couldn't find unexpired handle");
  }

  void invalidate_assoc(
                const string& OP,const string& handle) {
    if(lua_find_func(L, "invalidate_assoc")) {
      lua_pushstring(L, OP.c_str());
      lua_pushstring(L, handle.c_str());
      lua_call_func(L, 2, 0);
    }
  }

  void check_nonce(const string& OP,const string& nonce) {
    if(lua_find_func(L, "check_nonce")) {
      lua_pushstring(L, OP.c_str());
      lua_pushstring(L, nonce.c_str());
      if(lua_call_func(L, 2, 1)) {
        if (!lua_isnil(L, -1)) {
          throw opkele::id_res_bad_nonce(OPKELE_CP_ "old nonce used again - possible replay attack");
        } else {
          return;
        }
      }
    }
    // throw opkele::id_res_bad_nonce(OPKELE_CP_ "Could not check nonce - fail!");
  }

  /* Session perisistent store */

  void begin_queueing() {
    if(lua_find_func(L, "begin_queueing")) {
      lua_pushstring(L, asnonceid.c_str());
      lua_call_func(L, 1, 0);
    }
  }

  void queue_endpoint(const opkele::openid_endpoint_t& ep) {
    time_t rawtime;
    time (&rawtime);
    int expires_on = rawtime + 3600;  // allow nonce to exist for up to one hour without being returned
    if(lua_find_func(L, "queue_endpoint")) {
      lua_pushstring(L, asnonceid.c_str());
      lua_pushstring(L, ep.uri.c_str());
      lua_pushstring(L, ep.claimed_id.c_str());
      lua_pushstring(L, ep.local_id.c_str());
      lua_pushnumber(L, expires_on);
      lua_call_func(L, 5, 0); 
    }
  }

  void next_endpoint() {
    if(lua_find_func(L, "next_endpoint")) {
      lua_pushstring(L, asnonceid.c_str());
      lua_call_func(L, 1, 0);
    }
  }

  const openid_endpoint_t& get_endpoint() const {
    if(lua_find_func(L, "get_endpoint")) {
      lua_pushstring(L, asnonceid.c_str());
      if(lua_call_func(L, 1, 3) && !lua_isnil(L, -3)) {
        openid_endpoint_t *endpoint = new openid_endpoint_t();
        endpoint->uri = string(luaL_checkstring(L, -3));
        endpoint->claimed_id = string(luaL_checkstring(L, -2));
        endpoint->local_id = string(luaL_checkstring(L, -1));
        // FIXME: do we have a leak here ?
        return *endpoint;
      }
    }
    throw opkele::exception(OPKELE_CP_ "No more endpoints queued");
  }

  void set_normalized_id(const string& nid) {
    if(lua_find_func(L, "set_normalized_id")) {
      lua_pushstring(L, asnonceid.c_str());
      lua_pushstring(L, nid.c_str());
      lua_call_func(L, 2, 0);
    }
  }

  const string get_normalized_id() const {
    if(lua_find_func(L, "get_normalized_id")) {
      lua_pushstring(L, asnonceid.c_str());
      if(lua_call_func(L, 1, 1) && !lua_isnil(L, -1)) {
        return string(luaL_checkstring(L, -1));
      }
    }
    throw opkele::exception(OPKELE_CP_ "cannot get normalized id");
  }
  
  const string get_this_url() const {
    return serverurl;
  }

  void initiate(const string& usi) {
    prequeue_RP::initiate(usi);
  }
  
};

string random_secret = ""; // initialized at startup

int check_request_cookie(string str) {
  vector<string> comp = m2openid::explode(str, "-");
  uint64_t time_now = m2openid::timenow();
  uint64_t time_then;
  unsigned char hash[20];
  char hexstring[41];
  char *end;
  string calc;
  string test = comp[0] + "-" + comp[1] + "-" + random_secret;
  time_then = strtoull(comp[1].c_str(), &end, 10);
  if(time_then > time_now) {
    return 0;
  }
  if(time_now - time_then > 1000000L * 600) {
    return 0;
  }
  sha1::calc(test.c_str(), test.length(),hash); 
  sha1::toHexString(hash, hexstring);
  calc = hexstring;
  return (calc == comp[2]);
}

string get_request_cookie() {
  unsigned char hash[20];
  char hexstring[41];
  string s;
  string s1;
  uint64_t time_now = m2openid::timenow();
  std::stringstream ss;
  ss << time_now;

  m2openid::make_rstring(20, s); 
  s = s + "-" + ss.str();
  s1 = s + "-" + random_secret;
  sha1::calc(s1.c_str(), s1.length(),hash); 
  sha1::toHexString(hash, hexstring);
  s = s + "-" + hexstring;
  
  return s;
}

string start_auth(string usi, string onsuccess, string oncancel, string trust_root, string return_to) {
      // e.g. usi = "https://www.google.com/accounts/o8/id";
      opkele::sreg_t sreg(opkele::sreg_t::fields_NONE,opkele::sreg_t::fields_ALL);
      opkele::openid_message_t cm;
      string loc;
      string req_cookie = get_request_cookie();
      string return_to_full = return_to + "?request.cookie=" + req_cookie + "&onsuccess=" + onsuccess + "&oncancel=" + oncancel;
      m2_rp_t rp(req_cookie, return_to_full);
      rp.initiate(usi);
      loc = rp.checkid_(cm,opkele::mode_checkid_setup, return_to_full, trust_root, &sreg).append_query(rp.get_endpoint().uri);
      return loc;
}

/* If we return empty string, then it does not get to the browser.
 * If the string is non-empty - it will be put into Set-Cookie response.
 */
string auth_success(string nonce, string claimed_id) {
  string http_cookie_header = "";
  if(lua_find_func(L, "auth_success")) {
    lua_pushstring(L, nonce.c_str());
    lua_pushstring(L, claimed_id.c_str());
    if(lua_call_func(L, 2, 1) && !lua_isnil(L, -1)) {
      http_cookie_header = string(luaL_checkstring(L, -1));
    }
  }
  return http_cookie_header;
}


/* 
 * This function is called if something happened which should not have happened.
 * I.e. it is not a normal error, but someone is actively messing with the flow.
 * So we politely complain and tell not much more.
 * FIXME: some logging would be nice though.
 */
void send_terse_error(m2pp::connection &conn, m2pp::request req) {
  conn.reply_http(req, "<html><body><h1>Error</h1><p>One of the necessary parameters not supplied</p></body></html>", 
                 500, "Invalid parameters");
}

int main(int argc, char *argv[]) {

  std::string callbacks_file = (argc >= 2) ? argv[1] : "default.lua";

  std::string sender_id = "82209006-86FF-4982-B5EA-D1E29E55D481";
  std::string pub_spec = "tcp://127.0.0.1:8989";
  std::string sub_spec = "tcp://127.0.0.1:8988";

  m2openid::make_rstring(40, random_secret);
  L = lua_open();
  luaL_openlibs(L);

  if(luaL_loadfile(L, callbacks_file.c_str()) || lua_pcall(L, 0, 0, 0)) {
    lua_report_error(L);
    exit(1);
  }

  if(lua_find_func(L, "initialize")) {
    lua_pushstring(L, random_secret.c_str());
    if(lua_call_func(L, 1, 4)) {
      random_secret = luaL_checkstring(L, -4);
      sender_id = luaL_checkstring(L, -3);
      pub_spec = luaL_checkstring(L, -2);
      sub_spec = luaL_checkstring(L, -1);
    } else {
      exit(1);
    }
  } else {
    cout << "'initialize' Lua callback undefined\n";
    exit(1);
  }

  m2pp::connection conn(sender_id, pub_spec, sub_spec);
  while (1) {
    m2pp::request req = conn.recv();
    opkele::params_t headers = parsereq(req);
    opkele::params_t params;
    string query;

    if(headers["METHOD"] == "GET") {
      params = m2openid::parse_query_string(headers["QUERY"]);
    } else if(headers["METHOD"] == "POST") {
      params = m2openid::parse_query_string(req.body);
    }

    // if user is posting id (only openid_identifier will contain a value)
    if(params.has_param("openid_identifier") && 
          params.has_param("onsuccess") &&
          params.has_param("oncancel") &&
          params.has_param("trust_root") &&
          params.has_param("return_to") &&
          !params.has_param("openid.assoc_handle")) {
      std::vector<m2pp::header> reply_headers;
      string openid_id = params.get_param("openid_identifier");
      string onsuccess = params.get_param("onsuccess");
      string oncancel = params.get_param("oncancel");
      string trust_root = params.get_param("trust_root");
      string return_to = params.get_param("return_to");
      string loc = start_auth(openid_id, onsuccess, oncancel, trust_root, return_to);
      m2pp::header redirect_hdr("Location", loc);
      reply_headers.push_back(redirect_hdr);
      conn.reply_http(req, "", 302, "Redirect", reply_headers);
      
    } else if(params.has_param("openid.assoc_handle") && params.has_param("request.cookie") && params.has_param("onsuccess") && params.has_param("openid.return_to")) { 
      // user has been redirected, authenticate them and set cookie
      try {
        string req_cookie = params.get_param("request.cookie");
        if(check_request_cookie(req_cookie)) {
          m2_rp_t rp(req_cookie, params.get_param("openid.return_to"));
          std::vector<m2pp::header> reply_headers;
          rp.id_res(m2openid::m2openid_message_t(params));
          string cookie_value = auth_success(req_cookie, rp.get_claimed_id());
          if(cookie_value != "") {
            m2pp::header cookie_hdr("Set-Cookie", cookie_value);
            reply_headers.push_back(cookie_hdr);
          }
          m2pp::header redirect_hdr("Location", params.get_param("onsuccess"));
          reply_headers.push_back(redirect_hdr);
          conn.reply_http(req, "", 302, "Redirect", reply_headers);
        } else {
          /* protocol violation: bad cookie */
          /* FIXME: this can happen with the user error as well if they fall asleep while logging in ? */
          send_terse_error(conn, req);
        }
      } catch (opkele::exception &e) {
        /* Something really bad happened within opkele */
        send_terse_error(conn, req);
      }
    } else { //either the cancelled auth, or we are in error.
      if(params.has_param("openid.mode") && params.get_param("openid.mode") == "cancel" && params.has_param("oncancel")) {
        std::vector<m2pp::header> reply_headers;
        m2pp::header redirect_hdr("Location", params.get_param("oncancel"));
        reply_headers.push_back(redirect_hdr);
        conn.reply_http(req, "", 302, "Redirect", reply_headers);
      } else {
        send_terse_error(conn, req);
      }
    }

}

	return 0;
}

