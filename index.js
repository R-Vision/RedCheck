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
 * Convert some object to Array
 * @param obj
 * @returns {*}
 */
var toArray = function (obj) {
    if (!_.isEmpty(obj) && (_.isObject(obj) || _.isString(obj)) && !_.isArray(obj)) {
        obj = [obj];
    } else if (!_.isArray(obj)) {
        obj = [];
    }

    return obj;
};

/**
 * Convert property from item to array
 * @param item
 * @param property
 * @returns {Array}
 */
var toArrayFromProperty = function (item, property) {
    var result = [];

    if (item.hasOwnProperty(property)) {
        result = toArray(item[property]);
    }

    return result;
};

/**
 * Check result and execute callback
 * @param callback
 * @param err
 * @param result
 */
var runCallback = function (callback, err, result) {
    if (!err && _.isEmpty(result)) {
        err = new Error('Result is empty');
    }

    if (err) {
        callback(err);
    } else {
        callback(null, result);
    }
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
            return callback(error);
        }

        if (response.statusCode !== 200) {
            return callback(new Error('Status code is not 200'));
        }

        parseXml(body, function (err, xml) {
            if (!err) {
                if (xml.hasOwnProperty('error')) {
                    err = new Error(xml.error);
                } else if (xml.hasOwnProperty('message')) {
                    err = new Error(xml.message);
                }
            }

            if (err) {
                callback(err);
            } else {
                callback(null, response, xml);
            }
        });
    });
};

/**
 * info
 * @param callback
 */
RedCheck.prototype.info = function (callback) {
    this.get('info', function (err, response, data) {
        var result = {};

        if (!err) {
            if (data.hasOwnProperty('metadata')) {
                result = data.metadata;
            } else {
                err = new Error('metadata is undefined');
            }
        }

        runCallback(callback, err, result);
    });
};

/**
 * hosts
 * @param callback
 */
RedCheck.prototype.hosts = function (callback) {
    this.get('hosts', function (err, response, data) {
        var result = [];

        if (!err) {
            if (data.hasOwnProperty('hosts')) {
                var hosts = data.hosts;

                if (hosts.hasOwnProperty('host')) {
                    toArray(hosts.host).forEach(function (item) {
                        toArray(item).forEach(function (host) {
                            if (!_.isEmpty(host)) {
                                result.push(host);
                            }
                        });
                    });
                } else {
                    err = new Error('host is undefined');
                }
            } else {
                err = new Error('hosts is undefined');
            }
        }

        runCallback(callback, err, result);
    });
};

/**
 * scans
 * @param id
 * @param callback
 */
RedCheck.prototype.vulnerability = function (id, callback) {
    this.get('vulnerability/' + id, function (err, response, data) {
        var result = [];

        if (!err) {
            if (data.hasOwnProperty('scan_result')) {
                var scanResult = data.scan_result;

                if (scanResult.hasOwnProperty('vulnerability')) {
                    toArray(scanResult.vulnerability).forEach(function (vulnerability) {
                        if (!_.isEmpty(vulnerability)) {
                            result.push(vulnerability);
                        }
                    });
                } else {
                    err = new Error('vulnerability is undefined');
                }
            } else {
                err = new Error('scan_result is undefined');
            }
        }

        runCallback(callback, err, result);
    });
};

/**
 * definitions
 * @param id
 * @param callback
 */
RedCheck.prototype.definitions = function (id, callback) {
    this.get('definitions/' + id, function (err, response, data) {
        var result = {};

        if (!err) {
            if (data.hasOwnProperty('definitions')) {
                var definitions = data.definitions;

                if (definitions.hasOwnProperty('definition')) {
                    result = definitions.definition;

                    if (result.hasOwnProperty('reference')) {
                        result.reference = toArray(result.reference);
                    }
                } else {
                    err = new Error('definition is undefined');
                }
            } else {
                err = new Error('definitions is undefined');
            }
        }

        runCallback(callback, err, result);
    });
};

/**
 * patch
 * @param id
 * @param callback
 */
RedCheck.prototype.patch = function (id, callback) {
    this.get('patch/' + id, function (err, response, data) {
        var result = [];

        if (!err) {
            if (data.hasOwnProperty('scan_result')) {
                var scanResult = data.scan_result;

                if (scanResult.hasOwnProperty('patch')) {
                    toArray(scanResult.patch).forEach(function (patch) {
                        if (!_.isEmpty(patch)) {
                            if (patch.hasOwnProperty('detalization')) {
                                patch.detalization = toArrayFromProperty(patch.detalization, 'item');
                            }

                            if (patch.hasOwnProperty('products')) {
                                patch.products = toArrayFromProperty(patch.products, 'product');
                            }

                            result.push(patch);
                        }
                    });
                } else {
                    err = new Error('patch is undefined');
                }
            } else {
                err = new Error('scan_result is undefined');
            }
        }

        runCallback(callback, err, result);
    });
};

/**
 * inventory
 * @param id
 * @param callback
 */
RedCheck.prototype.inventory = function (id, callback) {
    this.get('inventory/' + id, function (err, response, data) {
        var result = [];

        if (!err) {
            if (data.hasOwnProperty('scan_result')) {
                var scanResult = data.scan_result;

                if (scanResult.hasOwnProperty('hardware')) {
                    result = scanResult.hardware;

                    if (result.hasOwnProperty('cpus')) {
                        result.cpus = toArrayFromProperty(result.cpus, 'cpu');
                    }

                    if (result.hasOwnProperty('memoryslots')) {
                        result.memoryslots = toArrayFromProperty(result.memoryslots, 'memoryslot');
                    }

                    if (result.hasOwnProperty('videocontrollers')) {
                        result.videocontrollers = toArrayFromProperty(result.videocontrollers, 'videocontroller');
                    }

                    if (result.hasOwnProperty('networkadapters')) {
                        result.networkadapters = toArrayFromProperty(result.networkadapters, 'adapter');
                    }

                    if (result.hasOwnProperty('physicaldrives')) {
                        result.physicaldrives = toArrayFromProperty(result.physicaldrives, 'drive');
                    }

                    if (result.hasOwnProperty('logicaldrives')) {
                        result.logicaldrives = toArrayFromProperty(result.logicaldrives, 'drive');
                    }
                } else {
                    err = new Error('hardware is undefined');
                }
            } else {
                err = new Error('scan_result is undefined');
            }
        }

        runCallback(callback, err, result);
    });
};

module.exports = RedCheck;
