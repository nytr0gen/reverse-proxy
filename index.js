const express = require('express');
const fs = require('fs');
const LRU = require('lru-cache');
const moment = require('moment');
const morgan = require('morgan');
const { parse: urlparse } = require('url');
const { program } = require('commander');
require('global-agent/bootstrap');

const got = require('got').extend({
    https: {
        rejectUnauthorized: false,
    },
    maxRedirects: 0,
    timeout: 20 * 1000, // 20s
    headers: {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.83 Safari/537.36',
    },
});

const cacheTimeSeconds = 60 * 60; // 60min
const cache = new LRU({
    max: 400, // 400 items
    ttl: cacheTimeSeconds * 1000,
});

const isAlphaNum = function(c) {
    return (
        ('0' <= c && c <= '9')
        || ('A' <= c && c <= 'Z')
        || ('a' <= c && c <= 'z')
    );
};

const numToHex = function(num) {
    return ('0' + num.toString(16)).slice(-2);
};

const encodeAllURI = function(s) {
    let ret = '';
    for (let i = 0; i < s.length; i++) {
        let c = s[i];
        if (!isAlphaNum(c) || 'admjADMJ'.includes(c)) {
            c = '%' + numToHex(c.charCodeAt(0));
        }

        ret += c;
    }

    return ret;
};

const htmlEncode = function(s) {
    let ret = '';
    for (let i = 0; i < s.length; i++) {
        let c = s[i];
        if (!isAlphaNum(c)) {
            c = `&#${c.charCodeAt(0)};`;
        }

        ret += c;
    }

    return ret;
};

const toSlug = function(s) {
    s = s.toLowerCase();
    s = s.replace(/[^a-z0-9]+/g, '-');
    if (s.startsWith('-')) {
        s = s.slice(1);
    }
    if (s.endsWith('-')) {
        s = s.slice(0, -1);
    }

    return s;
};

const getRawOutput = function(response, body) {
    let sent = response.req._header.trim().replace(/\n/g, '\n> ');
    sent = `> ${sent}\r\n>\r\n`;
    if (body) {
        sent += body + '\r\n';
    }

    let recv = `< HTTP/${response.httpVersion} ${response.statusCode} ${response.statusMessage}\r\n`;
    for (let i = 0; i < response.rawHeaders.length; i += 2) {
        recv += `< ${response.rawHeaders[i]}: ${response.rawHeaders[i+1]}\r\n`;
    }
    recv += '<\r\n';
    if (response.body) {
        recv += response.body;
    }

    return `${sent}\r\n${recv}`;
};

const fetch = async function(options) {
    try {
        const response = await got(options);

        return {
            body: response.body,
            statusCode: response.statusCode,
            headers: response.headers,
            rawOutput: getRawOutput(response, options.body),
        };
    } catch (err) {
        if (err.response) {
            return {
                body: err.response.body,
                statusCode: err.response.statusCode,
                headers: err.response.headers,
                rawOutput: getRawOutput(err.response, options.body),
            };
        }

        console.error(err);
        return {
            body: err.toString(),
            statusCode: 503,
            headers: {},
            rawOutput: `${options.url}\r\n${err.toString()}`,
        };
    }
};

const reverseProxyFetch = async function(url, host, options) {
    if (cache.has(url) && !url.includes('skipcache')) {
        const response = cache.get(url);
        response.headers['X-Cache-Status'] = 'HIT'; // replace MISS from cache

        return response;
    }

    const response = await fetch({ ...options, url });

    // improve body - replace any references to the new host
    const parts = ['https://', 'http://', '//', ''];
    for (let part of parts) {
        const rePart = new RegExp(`${part}${host}`, 'g');
        response.body = response.body.replace(rePart, `${part}${currentHost}`);

        if ('location' in response.headers) {
            response.headers['location'] = response.headers['location'].replace(rePart, `${part}${currentHost}`);
        }
    }

    // improve headers
    const headersBlacklist = [
        'content-encoding', 'connection',
        'transfer-encoding', 'content-length',
        'cache-control', 'expires', 'etag',
    ];
    for (const k of headersBlacklist) {
        if (k in response.headers) {
            delete response.headers[k];
        }
    }

    if ('set-cookie' in response.headers) {
        for (const i in response.headers['set-cookie']) {
            cookie = response.headers['set-cookie'][i];
            cookie = cookie.replace(/;\s*secure/i, '');
            response.headers['set-cookie'][i] = cookie;
        }
    }

    // improved caching - only static files
    const reStaticFile = /\.(?:jpg|jpeg|gif|png|ico|cur|gz|svg|svgz|mp4|ogg|ogv|webm|htc|css|js|map)(\?|$)/;
    const cacheableStatusCode = [404];
    if ((options.method === 'GET' && reStaticFile.test(url))
        || cacheableStatusCode.includes(response.statusCode)
    ) {
        response.headers['Cache-Control'] = `public, max-age=${cacheTimeSeconds}`;
        response.headers['X-Cache-Status'] = 'MISS';
        cache.set(url, response);
    }

    return response;
};

/**
 * Main App
 */
program
    .argument('<target>', 'target host + port http://example.com:80/')
    .option('-p, --port [port]', 'port number', '8191')
    .option('-h, --host [host]', 'local host', '127.0.0.1')
    .option('--logs', 'log every request inside ./logs')
    .action((target, opts) => {
        global.port = parseInt(opts.port, 10);
        global.currentHost = `${opts.host}:${port}`;
        global.isLoggingEnabled = !!opts.logs;

        const targetURL = urlparse(target);
        global.targetHost = targetURL.host;
        global.targetProto = targetURL.protocol;
        if (!targetHost || !targetProto) {
            throw new Error('invalid host or protocol');
        }
    });

program.parse();

const app = express();
app.disable('x-powered-by');

// catch all data
app.use(function(req, res, next) {
    req.rawBody = '';
    req.setEncoding('utf8');

    req.on('data', function(chunk) {
        req.rawBody += chunk;
    });

    req.on('end', function() {
        next();
    });
});
app.use(morgan('common'));

// TODO: maybe use /:host/:path(*) route and replace output
app.all(':path(*)', async function (req, res) {
    const { path } = req.params;
    if (!path.startsWith('/')) {
        path = '/' + path;
    }

    let query = '';
    const queryPos = req.originalUrl.indexOf('?');
    if (queryPos !== -1) {
        query = req.originalUrl.slice(queryPos);
    }

    const url = `${targetProto}//${targetHost}${path}${query}`;
    const method = req.method;

    const options = {
        method: req.method || 'GET',
        headers: { ...req.headers },
    };

    // improve headers
    const headersBlacklist = [
        'if-none-match', 'if-modified-since',
        'host', 'content-length',
    ];
    for (const k of headersBlacklist) {
        if (k in options.headers) {
            delete options.headers[k];
        }
    }

    // handle postdata
    if (options.method !== 'GET' && req.rawBody) {
        options.body = req.rawBody;
    }

    const response = await reverseProxyFetch(url, targetHost, options);
    res.set(response.headers);

    res.status(response.statusCode)
        .send(response.body);

    if (isLoggingEnabled) {
        // date +'%Y-%m-%d_%H.%M.%S'
        const date = moment().format('YYYY-MM-DD_HH.mm.ss');
        const pathSlug = toSlug(path).slice(0, 60);
        const logName = `${date}_${pathSlug}.log`;

        fs.promises.writeFile('./logs/' + logName, response.rawOutput)
            .catch(err => console.error(err));
    }
});

app.listen(port, () => {
    console.log(`[+] Listening at http://${currentHost}/`);
    console.log(`[+] Sending requests to ${targetProto}//${targetHost}`);
    console.log(`[+] Logging is ${isLoggingEnabled ? 'enabled' : 'disabled'}`);
});
