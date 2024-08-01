# oauth.zig #

http.zig helper app to hack implementing oauth2 with Microsoft auth endpoints

You will need an app registered with the Microsoft auth backend, and have access to the client id and secrets

redirect back to whatever you are running here - ie localhost:8080

# Env #

You will need to configure the following values in a file called `.env` 

AUTH_URL
CLIENT_ID
REDIRECT_URL
SCOPE
CLIENT_SECRET

If you dont have the `.env` file present, then `bun backend` wont build

# Using Bun for dev #

`bun install`

sets up tailwind / daisy UI etc

`bun tailwind` runs a watcher on the CSS, and generates tailwind output on the fly

`bun backend` runs a watcher on the Zig code, recompiles and relaunches on demand

# Just plain build #

`zig build`

`zig build run`
