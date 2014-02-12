Introduction
====
This module for proxy_store、fastcgi_store、scgi_store、uwsgi_store extension, provides multiple directory  to store,  add or delete the directory dynamically .

(Dynamically add directory needs to be created in advance and the directory permissions must be the worker can access)


Requirements
====
[ngx_consistent_hash](https://github.com/agile6v/ngx_consistent_hash)  



Installation
====
./configure --add-module=/path/to/ngx_http_store_plusplus --add-module=/path/to/ngx_consistent_hash



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


