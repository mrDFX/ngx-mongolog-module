## About
`ngx_mongolog_module` is a module which allows `nginx` to write log directly to `MongoDB` database.

## Status
Experimental

## Configuration directives
Add to http { } section:
```
mongolog_address    "mongodb://[user:pass@]localhost:27017/";  
mongolog_database   "test";  
mongolog_collection "test";  
mongolog_format	timestamp time_local request_time msec server_name
				remote_addr request_uri request_args http_status user_agent
				http_referer is_internal method_name http_protocol request_length
				bytes_sent body_bytes_sent upstream_addr upstream_response_time
				headers_in headers_out request_body;
```
### mongolog_format
```
timestamp - mongo insert timestamp
time_local - nginx $time_local in str format
request_time - nginx $request_time in str format
msec - nginx $msec in str format
server_name - $server_name variable
remote_addr - client address
request_uri - request_uri
request_args - GET parameters
http_status - response status
user_agent - User-Agent request header
http_referer - Referer request header
is_internal - is this query internal
method_name - POST/GET/PUT/DELETE etc
http_protocol - str HTTP version
request_length - got bytes from client
bytes_sent - send bytes to client
body_bytes_sent - send bytes to client, excluding headers
upstream_addr - upstream sock addr
upstream_response_time - str miliseconds
headers_in - request headers
headers_out - response headers (known issue: not all headers exists in log)
request_body - POST parameters
```
