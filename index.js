'use strict';

var url = require('url');
var _ = require('lodash');
var parseString = require('xml2js').parseString;
var request = require('request');

/**
 * parseXml
 * @param body
 * @param callback
 */
var parseXml = function (body, callback) {
    var options = {
        // (default: false):
        // Trim the whitespace at the beginning and end of text nodes.
        trim: true,

        // (default: false):
        // Normalize all tag names to lowercase.
        normalizeTags: true,

        // (default: false):
        // Trim whitespaces inside text nodes.
        normalize: true,

        // (default: true):
        // Set this if you want to get the root node in the resulting object.
        explicitRoot: false,

        // (default: ''):
        // what will the value of empty nodes be.
        emptyTag: null,

        // (default: true):
        // Always put child nodes in an array if true;
        // otherwise an array is created only if there is more than one.
        explicitArray: false,

        // (default: false):
        // Merge attributes and child elements as properties of the parent,
        // instead of keying attributes off a child attribute object.
        mergeAttrs: true
    };

    parseString(body, options, callback);
};

/**
 * RedCheck
 * @param options
 * @constructor
 */
function RedCheck(options) {
    var baseUrl;

    if (_.isString(options)) {
        baseUrl = options;
    } else {
        baseUrl = url.format(options);
    }

    var headers = options.headers || {};

    if (options.hasOwnProperty('password')) {
        headers['X-RedKey'] = options.password;
    }

    var requestOptions = {
        baseUrl: baseUrl
    };

    if (!_.isEmpty(headers)) {
        requestOptions.headers = headers;
    }

    this.request = request.defaults(requestOptions);
}

/**
 * get
 * @param url
 * @param callback
 */
RedCheck.prototype.get = function (url, callback) {
    this.request.get(url, function (error, response, body) {
        if (error) {
            callback(error);
            return;
        }

        if (response.statusCode !== 200) {
            callback(new Error(''));
            return;
        }

        parseXml(body, function (err, xml) {
            if (err) {
                callback(err);
                return;
            }

            if (xml.hasOwnProperty('error')) {
                callback(new Error(xml.error));
                return;
            }

            if (xml.hasOwnProperty('message')) {
                callback(new Error(xml.message));
                return;
            }

            callback(error, response, xml);
        });
    });
};

/**
 * info
 * @param callback
 */
RedCheck.prototype.info = function (callback) {
    this.get('info', callback);
};

/**
 * hosts
 * @param callback
 */
RedCheck.prototype.hosts = function (callback) {
    this.get('hosts', function (err, response, data) {
        if (err) {
            callback(err);
            return;
        }

        if (data.hasOwnProperty('hosts')) {
            if (!_.isEmpty(data.hosts) && _.isObject(data.hosts) && !_.isArray(data.hosts)) {
                data.hosts = [data.hosts];
            }
        }

        callback(err, response, data);
    });
};

/**
 * scans
 * @param id
 * @param callback
 */
RedCheck.prototype.vulnerability = function (id, callback) {
    this.get('vulnerability/' + id, function (err, response, data) {
        if (err) {
            callback(err);
            return;
        }

        if (data.hasOwnProperty('scan_result') && data.scan_result.hasOwnProperty('vulnerability')) {
            var vulnerability = data.scan_result.vulnerability;

            if (!_.isEmpty(vulnerability) && _.isObject(vulnerability) && !_.isArray(vulnerability)) {
                data.scan_result.vulnerability = [vulnerability];
            }
        }

        callback(err, response, data);
    });
};

/**
 * definitions
 * @param id
 * @param callback
 */
RedCheck.prototype.definitions = function (id, callback) {
    this.get('definitions/' + id, callback);
};

/**
 * patch
 * @param id
 * @param callback
 */
RedCheck.prototype.patch = function (id, callback) {
    this.get('patch/' + id, callback);
};

/**
 * inventory
 * @param id
 * @param callback
 */
RedCheck.prototype.inventory = function (id, callback) {
    this.get('inventory/' + id, callback);
};

module.exports = RedCheck;
