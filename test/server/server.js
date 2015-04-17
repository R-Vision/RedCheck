'use strict';

var http = require('http');
var url = require('url');
var fs = require('fs');
var path = require('path');

var getFileById = function (dir, id) {
    var filePath = path.join(__dirname, dir, id.toString() + '.xml');
    return fs.readFileSync(filePath, 'utf8');
};

http.createServer(function (req, res) {
    var pathname = url.parse(req.url).pathname;

    res.writeHead(200, {
        'Content-Type': 'application/xml; charset=utf-8',
        Server: 'Microsoft-HTTPAPI/2.0',
        Date: new Date()
    });

    var data;
    var uri = pathname.split('/');

    try {
        switch (uri[2]) {
            case 'info':
                data = getFileById(uri[2], 'info');
                break;
            case 'hosts':
                data = getFileById(uri[2], 'hosts');
                break;
            case 'vulnerability':
            case 'patch':
            case 'inventory':
            case 'definitions':
                data = getFileById(uri[2], parseInt(uri[3], 10));
                break;
            default:
                data = '<redcheck><message>Route not found</message></redcheck>';
                break;
        }
    } catch (err) {
        data = '<redcheck><message>' + err.toString() + '</message></redcheck>';
    }

    res.end(data);
}).listen(4142);
