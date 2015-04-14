# RedCheck

### Install

```bash
npm install redcheck
```

### Usage

```javascript
var RedCheck = require('redcheck');

var redcheck = new RedCheck({
    hostname: 'YourHost',
    protocol: 'http',
    port: 4142,
    pathname: '/redcheck',
    password: 'YourPassword'
});

redcheck.info(function (err, info) {
    if (err) {
        console.error(err);
    } else {
        console.log(info);
    }
});
```

### Other methods
Get all hosts
```javascript
redcheck.hosts(function (err, hosts) {
    if (err) {
        console.error(err);
    } else {
        console.log(hosts);
    }
});
```

Get all vulnerabilities in host
```javascript
redcheck.vulnerability(hostId, function (err, data) {
    if (err) {
        console.error(err);
    } else {
        console.log(data);
    }
});
```

Get all definitions in host
```javascript
redcheck.definitions(hostId, function (err, data) {
    if (err) {
        console.error(err);
    } else {
        console.log(data);
    }
});
```

Get all patches in host
```javascript
redcheck.patch(hostId, function (err, data) {
    if (err) {
        console.error(err);
    } else {
        console.log(data);
    }
});
```

Get inventory report in host
```javascript
redcheck.inventory(hostId, function (err, data) {
    if (err) {
        console.error(err);
    } else {
        console.log(data);
    }
});
```

### Dependencies
* request
* xml2js
* lodash