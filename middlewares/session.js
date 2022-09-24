import util from 'util';
import express_session from 'express-session';
import { SessionAPI } from "@nfjs/back";

function session(options) {
    const ex_sess = express_session(options);
    const x = util.promisify(ex_sess);
    return async function (context) {
        await x(context.req, context.res);
        context.session = new SessionAPI(context.req.session);
    };
}

export default session;
