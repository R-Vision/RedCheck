/* jshint -W030 */
/* jshint node:true, mocha:true */
/* eslint-env node, mocha */
/* eslint no-unused-expressions: 0 */

'use strict';

var should = require('should');
var RedCheck = require('../index.js');

var redcheck = new RedCheck({
    hostname: 'altxtst.cloudapp.net',
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
        var response = null;
        var data = null;

        before(function (done) {
            redcheck.info(function (err, res, body) {
                should.not.exist(err);
                should.exist(res);
                should.exist(body);
                response = res;
                data = body;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Код ответа должен быть 200', function () {
            response.should.have.property('statusCode').and.be.exactly(200).and.be.a.Number;
        });

        it('XML должен содержать metadata в корне', function () {
            data.should.have.property('metadata');
        });

        it('XML должен содержать информаци о версии RedCheck', function () {
            data.should.have.property('metadata').and.have.property('redcheck_version');
        });
    });

    describe('#hosts', function () {
        var response = null;
        var data = null;

        before(function (done) {
            redcheck.hosts(function (err, res, body) {
                should.not.exist(err);
                should.exist(res);
                should.exist(body);
                response = res;
                data = body;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Код ответа должен быть 200', function () {
            response.should.have.property('statusCode').and.be.exactly(200).and.be.a.Number;
        });

        it('XML должен содержать hosts в корне', function () {
            data.should.have.property('hosts').and.be.a.Array;
        });

        it('Внутри hosts должны быть объекты host', function () {
            data.hosts.forEach(function (host) {
                host.should.have.property('host').and.be.a.Array;
            });
        });

        it('Внутри host должны бы id', function () {
            data.hosts.forEach(function (item) {
                item.host.forEach(function (item) {
                    item.should.have.property('id');
                    hostsIds.push(item.id);
                });
            });
        });
    });

    describe('#vulnerability', function () {
        var response = null;
        var data = null;

        before(function (done) {
            hostsIds.should.be.a.Array;

            var hostId = hostsIds[Math.floor(Math.random() * hostsIds.length)];

            if (parseInt(hostId, 10) === 5) {
                hostId = 1;
            }

            console.log('    #host id: ' + hostId);

            redcheck.vulnerability(hostId, function (err, res, body) {
                should.not.exist(err);
                should.exist(res);
                should.exist(body);
                response = res;
                data = body;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Код ответа должен быть 200', function () {
            response.should.have.property('statusCode').and.be.exactly(200).and.be.a.Number;
        });

        it('XML должен содержать scan_result в корне', function () {
            data.should.have.property('scan_result');
        });

        it('XML должен содержать перечень уязвимостей', function () {
            data.should.have.property('scan_result').and.have.property('vulnerability').and.be.a.Array;
        });

        it('Описание каждой уязвимости должно содержать altx_id и version', function () {
            data.scan_result.vulnerability.forEach(function (vulnerability) {
                vulnerability.should.be.a.Object.and.have.property('altx_id');
                vulnerability.should.be.a.Object.and.have.property('version');

                altxIds.push(vulnerability.altx_id);
            });
        });
    });

    describe('#patch', function () {
        var response = null;
        var data = null;

        before(function (done) {
            hostsIds.should.be.a.Array;

            var hostId = hostsIds[Math.floor(Math.random() * hostsIds.length)];

            if (parseInt(hostId, 10) === 2) {
                hostId = 1;
            }

            console.log('    #host id: ' + hostId);

            redcheck.patch(hostId, function (err, res, body) {
                should.not.exist(err);
                should.exist(res);
                should.exist(body);
                response = res;
                data = body;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Код ответа должен быть 200', function () {
            response.should.have.property('statusCode').and.be.exactly(200).and.be.a.Number;
        });

        it('XML должен содержать scan_result в корне', function () {
            data.should.have.property('scan_result');
        });
    });

    describe('#inventory', function () {
        var response = null;
        var data = null;

        before(function (done) {
            hostsIds.should.be.a.Array;

            var hostId = hostsIds[Math.floor(Math.random() * hostsIds.length)];

            if (parseInt(hostId, 10) === 5) {
                hostId = 1;
            }

            console.log('    #host id: ' + hostId);

            redcheck.inventory(hostId, function (err, res, body) {
                should.not.exist(err);
                should.exist(res);
                should.exist(body);
                response = res;
                data = body;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Код ответа должен быть 200', function () {
            response.should.have.property('statusCode').and.be.exactly(200).and.be.a.Number;
        });

        it('XML должен содержать scan_result в корне', function () {
            data.should.have.property('scan_result');
        });
    });

    describe('#definitions', function () {
        var response = null;
        var data = null;

        before(function (done) {
            altxIds.should.be.a.Array;

            var altxId = altxIds[Math.floor(Math.random() * altxIds.length)];

            console.log('    #altx id: ' + altxId);

            redcheck.definitions(altxId, function (err, res, body) {
                should.not.exist(err);
                should.exist(res);
                should.exist(body);
                response = res;
                data = body;
                // console.log(JSON.stringify(data, null, 2));
                done();
            });
        });

        it('Код ответа должен быть 200', function () {
            response.should.have.property('statusCode').and.be.exactly(200).and.be.a.Number;
        });

        it('XML должен содержать подробное описание уязвимости', function () {
            data.should.have.property('definitions').and.be.a.Object.and.have.property('definition');
        });
    });
});
