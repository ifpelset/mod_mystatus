## mod_mystatus
> A apache(httpd) status module that really realtime, I just handle to output specific url connection count and bandwidth.

### Dependency
[cJSON](https://github.com/DaveGamble/cJSON), Ultralightweight JSON parser in ANSI C 

### Compilation && Install
#### Linux
- Compilation

```python 

# I have built a static lib if you use CentOS 7, use it.
apxs -c mod_mystatus.c -Ilinux/cJSON -Llinux/cJSON -lcjson -lm
# or
# You can build cJSON.c when build mod_mystatus.c, but mod_mystatus.c should be first location.
apxs -c mod_mystatus.c linux/cJSON/cJSON.c -Ilinux/cJSON -lm 

```
- Install

```python
[sudo] apxs -i -a mod_mystatus.la
```
- Configuration

Just add the following content into httpd.conf

```python
<Location "/mystatus">
    SetHandler mystatus-handler
</Location>
```

#### Windows
- Configure apxs
-   123

- Compilation && Install

```python
apxs -c -i -a mod_mystatus.c -Iwindows/cJSON -Lwindows/cJSON
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
