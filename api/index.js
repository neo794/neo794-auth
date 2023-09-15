import { common } from "@nfjs/core";
import { authProviders } from "../index.js";
import { dbapi } from "@nfjs/back";

class pfSingleAuth {
    async login(context) {
        try {
            const data = await dbapi.query(`select pf.f4users8auth(:ps_data) as res`, { ps_data: context.body.args }, { context: context });
            context.session.assign('auth',data.data[0].res);
            return { result: true, detail: data.data[0].res };
        } catch (e) {
            return { result: false, detail: e };
        }
    }

    async logout(session) {
        session.destroy();
        return false;
    }

    static requestCheck(req, res, next) {
        if (common.getPath(req, 'cachedObj.attributes.unauthorized') === undefined && !req.session.authProvider) {
            res.sendStatus(401);
            return;
        }
        next();
    }

    getUserInfo(session, params) {
        if (session.get('authProvider')) {
            return authProviders[session.get('authProvider')].getUserInfo(session, params);
        }
        return {};
    }

    static async checkVerify(context) {
        try {
            const key_token = context.session.get('auth.key');
            const user_id = context.session.get('auth.user_id');
            const data = await dbapi.query(`select pf.f4users8check_session(:user_id,:key_token) as res`, { user_id, key_token }, { context: context });
            context.session.assign('auth',{ user_settings: data.data[0].res.settings });
            return data.data[0].res.res;
        } catch (e) {
            return false;
        }
    }

    static async authMiddleware(context) {
        const checkData = await pfSingleAuth.checkVerify(context);
        if (checkData) {
            return true;
        } else {
            context.session.destroy();
            context.code(401);
            context.end();
            return false;
        }
    }
}

export default pfSingleAuth;