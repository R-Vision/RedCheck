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

redcheck.info(function (err, result) {
    if (err) {
        console.error(err);
    } else {
        console.log(result);
    }
});
```

### Other methods
Get all hosts
```javascript
redcheck.hosts(function (err, result) {
    if (err) {
        console.error(err);
    } else {
        console.log(result);
    }
});
```

Get all vulnerabilities in host
```javascript
redcheck.vulnerability(hostId, function (err, result) {
    if (err) {
        console.error(err);
    } else {
        console.log(result);
    }
});
```

Get all definitions in host
```javascript
redcheck.definitions(hostId, function (err, result) {
    if (err) {
        console.error(err);
    } else {
        console.log(result);
    }
});
```

Get all patches in host
```javascript
redcheck.patch(hostId, function (err, result) {
    if (err) {
        console.error(err);
    } else {
        console.log(result);
    }
});
```

Get inventory report in host
```javascript
redcheck.inventory(hostId, function (err, result) {
    if (err) {
        console.error(err);
    } else {
        console.log(result);
    }
});
```

### Dependencies
* request
* xml2js
* lodash