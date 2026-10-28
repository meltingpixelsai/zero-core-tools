// Not the real wagmi. x402 lists wagmi as a dependency but never imports it, so package.json replaces it with this
// placeholder to keep its wallet SDKs, including the proprietary @metamask/sdk, out of the install.
// If anything ever loads it, fail loudly instead of running without it.
throw new Error('wagmi is stubbed out (see package.json overrides and stubs/wagmi-unused); something tried to load it');
