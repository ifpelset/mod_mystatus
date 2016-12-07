## mod_mystatus
> A apache(httpd) status module that really realtime, I just handle to output specific url connection count and bandwidth.

### Dependency
[cJSON](https://github.com/DaveGamble/cJSON), Ultralightweight JSON parser in ANSI C 

### Compilation && Install
- Compilation

```python
apxs -c mod_mystatus.c -I[Your cJSON include file directory] -L[Your cJSON static lib directory] -lcjson -lm
```
- Install

```python
apxs -i -a mod_mystatus.la
```
- Configuration
    Just add the following content into httpd.conf

```python
<Location "/mystatus">
    SetHandler mystatus-handler
</Location>
```

### Usage

    Use http client to send a post request to http://your ip/mystatus, request content is a json string, it contains a request regex expression, as following:

```javascript
{
    "pattern": "^/a.avi$"
}
```

### Screenshot
![result](result.png)
