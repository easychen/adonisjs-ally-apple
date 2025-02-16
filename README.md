# Adonis Ally - Apple Sign In Driver

> adonis, adonis-ally, apple

[![npm-image]][npm-url] [![license-image]][license-url] ![typescript-image]

This driver extends Adonis Ally and allows to integrate Apple Sign In.

## Installation

```bash
npm install easy-adonisjs-ally-apple
# or
yarn add easy-adonisjs-ally-apple
```

As the package has been installed, you have to configure it by running a command:

```bash
node ace configure @c0ldplasma/adonis-ally-apple
```

Then open the `env.ts` file and paste the following code inside the `Env.rules` object.

```ts
APPLE_APP_CLIENT_ID: Env.schema.string(),
APPLE_WEB_SERVICES_ID: Env.schema.string(),
APPLE_TEAM_ID: Env.schema.string(),
APPLE_KEY_ID: Env.schema.string(),
APPLE_PRIVATE_KEY: Env.schema.string(),
```

And don't forget to add these variables to your `.env` and `.env.sample` files.

## Usage

Apple Driver environment variables have some specific usage:

- `APPLE_PRIVATE_KEY` - your app private key that you should download from [here](https://developer.apple.com/account/resources/authkeys/list)
- `APPLE_KEY_ID` - the id of the key you downloaded earlier, it can be found on the same page
- `APPLE_TEAM_ID` - you teams' id in Apple system, it can be found [here](https://developer.apple.com/account/#/membership)
- `APPLE_APP_CLIENT_ID` - your app idenifier, for ex: com.adonis.ally
- `APPLE_WEB_SERVICES_ID` - web services idenifier, for ex: com.adonis.ally.signin

For usage examples for Adonis Ally and its methods consult Adonis.js [official docs](https://docs.adonisjs.com/guides/authentication/social-authentication).

[npm-image]: https://img.shields.io/npm/v/easy-adonisjs-ally-apple.svg?style=for-the-badge&logo=npm
[npm-url]: https://npmjs.org/package/easy-adonisjs-ally-apple 'npm'
[license-image]: https://img.shields.io/npm/l/easy-adonisjs-ally-apple?color=blueviolet&style=for-the-badge
[license-url]: LICENSE 'license'
[typescript-image]: https://img.shields.io/badge/Typescript-294E80.svg?style=for-the-badge&logo=typescript
[typescript-url]: "typescript"
