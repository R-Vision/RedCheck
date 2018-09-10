/* jshint -W030 */
/* jshint node:true, mocha:true */
/* eslint-env node, mocha */
/* eslint no-unused-expressions: 0 */

'use strict';

var should = require('should');
var RedCheck = require('../index.js');

const testIds = {
    windows: 1,
    linux: 13,
    cisco: 15
};

/*var redcheck = new RedCheck({
    hostname: 'altxtst.cloudapp.net',
    protocol: 'http',
    port: 4142,
    pathname: '/redcheck',
    password: '{939C3C85-5D14-4AA5-ACAF-0020891D8FFF}'
});*/

var redcheck = new RedCheck({
    hostname: 'localhost',
    protocol: 'http',
    port: 4142,
    pathname: '/redcheck',
    password: '{939C3C85-5D14-4AA5-ACAF-0020891D8FFF}'
});

describe('RedCheck', function () {
    this.timeout(10000);

    var hostsIds = [];
    var altxIds = [];

    describe('#info', function () {
        var data = null;

        before(function (done) {
            redcheck.info(function (err, result) {
                should.not.exist(err);
                data = result;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Result should have property redcheck_version', function () {
            data.should.have.property('redcheck_version');
        });
    });

    describe('#hosts', function () {
        var data = null;

        before(function (done) {
            redcheck.hosts(function (err, result) {
                should.not.exist(err);
                data = result;
                // console.log(JSON.stringify(hosts, null, 2));
                done();
            });
        });

        it('Result should be an Array', function () {
            data.should.be.a.Array;
        });

        it('Each host should have property id', function () {
            data.forEach(function (host) {
                host.should.have.property('id');
                hostsIds.push(host.id);
            });
        });
    });

    describe('#vulnerability', function () {
        var data = null;

        before(function (done) {
            hostsIds.should.be.a.Array;

            var hostId = parseInt(hostsIds[Math.floor(Math.random() * hostsIds.length)], 10);

            hostId = 1;
            should(hostId).be.a.Number;
            console.log('    #host id: ' + hostId);

            redcheck.vulnerability(hostId, function (err, result) {
                should.not.exist(err);
                data = result;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Result should be an Array', function () {
            data.should.be.a.Array;
        });

        it('Each vulnerability should be an Object and have property altx_id and version', function () {
            data.forEach(function (vulnerability) {
                vulnerability.should.be.a.Object.and.have.property('altx_id');
                vulnerability.should.be.a.Object.and.have.property('version');

                altxIds.push(vulnerability.altx_id);
            });
        });
    });

    describe('#patch', function () {
        var data = null;

        before(function (done) {
            hostsIds.should.be.a.Array;

            var hostId = hostsIds[Math.floor(Math.random() * hostsIds.length)];

            hostId = 1;
            console.log('    #host id: ' + hostId);

            redcheck.patch(hostId, function (err, result) {
                should.not.exist(err);
                data = result;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Result should be an Array', function () {
            data.should.be.a.Array;
        });
    });

    describe('#inventory required fields', function () {
        function checkRequiredFields(err, result) {
            should.not.exist(err);

            result.should.be.an.Object;
            result.should.have.property('networkadapters').which.is.an.Array.and.not.empty;

            result.should.have.property('os').which.is.an.Object.and.not.empty;
        }

        it('*windows result should have required fields', function (done) {
            redcheck.inventory(testIds.windows, function (err, result) {
                checkRequiredFields(err, result);
                done();
            });
        });

        it('*linux result should have required fields', function (done) {
            redcheck.inventory(testIds.linux, function (err, result) {
                checkRequiredFields(err, result);
                done();
            });
        });

        it('*cisco result should have required fields', function (done) {
            redcheck.inventory(testIds.cisco, function (err, result) {
                checkRequiredFields(err, result);
                done();
            });
        });
    });

    describe('#definitions', function () {
        var data;

        before(function (done) {
            altxIds.should.be.a.Array;

            var altxId = parseInt(altxIds[Math.floor(Math.random() * altxIds.length)], 10);

            should(altxId).be.a.Number;

            console.log('    #altx id: ' + altxId);

            redcheck.definitions(altxId, function (err, result) {
                should.not.exist(err);
                data = result;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Result should be an Object', function () {
            data.should.be.a.Object;
        });
    });
});
