import { api, common, config } from "@nfjs/core"
import { web } from "@nfjs/back";
import { NFAuth } from "./index.js";
import session from "./middlewares/session.js";
import express_session from 'express-session';
import session_file_store from "session-file-store";
const FileStore = session_file_store(express_session);
import connect_redis from "connect-redis";
const RedisStore = connect_redis(express_session);

async function init() {

    // TODO: используется для авторизации в экшене, переписать
    // common.setPath(nf, 'sandbox.auth', auth);
    api.setAppRouteMid('action', NFAuth.requestCheck, 30);
    api.setAppRouteMid('dataset', NFAuth.requestCheck, 30);
    web.registerMiddleware('auth', NFAuth.authMiddleware);
    const moduleConfig = common.getPath(config, '@nfjs/auth') || {};
    moduleConfig.session = moduleConfig.session || {};

    let { secure, sameSite, maxAge } = moduleConfig.session;
    let cookie = { secure, sameSite, maxAge: maxAge && +maxAge };

    let sessionStore = moduleConfig.session?.store =='redis' ? createRedisSessionStore(config) : new FileStore({ logFn: () => { } });
    let sessionOptions = {
        cookie,
        secret: 'n5 secret',
        resave: false,
        rolling: true,
        saveUninitialized: false,
        store: sessionStore
    };

    web.registerMiddleware('session', session(sessionOptions));
}

function createRedisSessionStore(config) {
    if (!config.redis) throw new Error('Отсутствуют настройки подключения к Redis.');

    /** @type {Function} redisRetryStrategy
     *
     * @param {Object} options
     * @param {String} options.error.code
     * @param {Number} options.total_retry_time
     * @param {Number} options.attempt
     * @return {number|Error|undefined}
     */
    const retryStrategy = options => {
        if (options.error && options.error.code === 'ECONNREFUSED' && options.attempt > 10) {
            return new Error('The server refused the connection');
        }
        if (options.total_retry_time > 1000 * 60 * 60) {
            return new Error('Retry time exhausted');
        }
        if (options.attempt > 10) {
            return undefined;
        }
        return 1000;
    };

    const redisClient = redis.createClient({
        ...config.redis,
        retry_strategy: retryStrategy,
    });

    redisClient.on('error', console.error); // TODO: надо логировать

    const onSigintSigtermMessage = signal => {
        return msg => {
            if ('message' === signal && 'shutdown' !== msg) return; // windows
            redisClient.quit(err => {
                if (err) {
                    console.error(err);
                    return process.exit(1);
                }
                process.exit(0);
            });
        }
    };

    process
        .on('SIGTERM', onSigintSigtermMessage('SIGTERM'))
        .on('SIGINT', onSigintSigtermMessage('SIGINT'))
        .on('message', onSigintSigtermMessage('message'));

    return new RedisStore({ client: redisClient });
}

export { init };
