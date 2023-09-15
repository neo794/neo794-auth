import pfSingleAuth from "./api/index.js";

const auth = new pfSingleAuth();
const authProviders = {};

export {auth, authProviders, pfSingleAuth};