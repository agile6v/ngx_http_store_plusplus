Introduction
====
This module for proxy_store | fastcgi_store | scgi_store | uwsgi_store extension, provides multiple directory to store and add or delete the directory dynamically.

(Dynamically add directory needs to be created in advance and the directory permissions must be the worker can access.)


Requirements
====
[ngx_consistent_hash](https://github.com/agile6v/ngx_consistent_hash)  



Installation
====
`./configure --add-module=/path/to/ngx_http_store_plusplus                
             --add-module=/path/to/ngx_consistent_hash`   


Directives
====

store_plusplus
--------------------
**syntax:** *store_plusplus;*

**default:** *-*

**context:** *location*

Turns on directory add or delete interface.

store_plusplus_conhash_zone
--------------------
**syntax:** *store_plusplus_conhash_zone keys_zone=name:size [vnodecnt=count]*

**default:** *-*

**context:** *http*

Sets the share memory name、share memory size and vnode count of the consistent hash.

If you explicitly specifly the vnodecnt, it cannot be more than 10000. By default, vnodecnt is set to 100.

NOTE: If you want to use the ngx_consistent_hash module must be defined in a similar directive.

store_plusplus_dir
--------------------
**syntax:** *store_plusplus_dir { ... }*

**default:** *-*

**context:** *http*

Storage directory listing.

Sample Configuration
====
```bash
http {
    store_plusplus_dir {
        /cache1/;
        /cache2/;
        /cache3/;
        /cache4/;
    }

    store_plusplus_conhash_zone keys_zone=storeplusplus:2m;

    server {
        listen       80;
        server_name  localhost;

        location / {
            root $store_plusplus_file_path;
            add_header StoreStatus "HIT";
            proxy_store on;

            if ( !-e $request_filename ) {
                add_header StoreStatus "MISS";
                proxy_pass http://127.0.0.1:25000/$uri;
            }
        }

        location /store_view {
            store_plusplus;
        }
    }
}
```


Testing
====
```bash
add:       curl -s "http://127.0.0.1/store_view?cmd=1&value=/cache5/"
del:       curl -s "http://127.0.0.1/store_view?cmd=2&value=/cache5/"
traverse:  curl -s "http://127.0.0.1/store_view?cmd=3"

### add path
$ curl -s "http://127.0.0.1/store_view?cmd=1&value=/cache5/"
Add node successfully!

### del path
$ curl -s "http://127.0.0.1/store_view?cmd=2&value=/cache5/"
Delete node successfully!

### traverse vnode
$ curl -s "http://127.0.0.1/conhash?cmd=3" -o allpaths.txt
$ cat allpaths.txt


```


See also
========
* [ngx_consistent_hash][]

[ngx_consistent_hash]: https://github.com/agile6v/ngx_consistent_hash


