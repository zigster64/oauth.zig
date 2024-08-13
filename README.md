# oauth.zig #

http.zig helper app implementing oauth2 with Microsoft auth endpoints

This is proof of concept for doing automatic session management with a http.zig backend, using HTMX

You will need an app registered with the Microsoft auth backend, and have access to the client id and secrets

redirect back to whatever you are running here - ie localhost:8080

If there is enough interest, I might convert this into a session library that sits on top of http.zig. 

# Auth Flow and Security #


- User hits a protected route
- Middleware checks if session cookie set, if so - validate it, and render the route as per normal

if not authorized :

- generate an anonymous session with a unique ID, and capture the client IP address and requested URL. Anon sessions have a TTL of 30 seconds
- returns HTML content to render a login link (3rd party auth server), with a ref to our anon SESSION_ID
- User clicks on the link, does their authentication, and it redirects back to our app at /zauth?code=....&state=SESSION_ID
- Our app collects the auth code, and calls the 3rd party service to exchange it for a token, AND a refresh token
- Our app decodes the 3rd party token (without signature verification), and creates a new active session
- Our app bundles the SESSION_ID, username, email, IP address, etc into a struct, and digitally signs it with our own JWT_SECRET
- Our app sets the signed / encoded token as a http-only cookie on the browser, and redirects them to the original URL

So what we end up with is backend middleware that automatically intercepts hits on protected routes, and presents a login button
if the user is not authenicated.

If the user correctly logs in via 3rd party, the same middleware manages session creation, and redirects to the original URL.

Using Sessions gives us the control to manage and track who the active users are and what they are doing (in the DB)

Using http-only cookies rather than authorization headers means nothing fancy to do in the HTMX frontend to propogate the session, and cant access the cookie from the JS console

Encoding the SESSION_ID + user details in a JWT, and signing it means that an attacker cannot simply alter the session details to hack a new session


## Optional - IP Address Stamping ## 

The Original IP address of the anon client is encoded into the signed cookie as well - so an attacker that captured the session cookie would not be able 
to replay it unless they also managed to spoof the original client's IP address.

So if the user is say - on mobile internet and roaming from one hotspot to another - their session will invalidate as soon as they jump hotspots / get a new IP. 

This is wanted for the target application in this case, but might be overkill for your needs. Adjust accordingly.



# Env #

You will need to configure the following values in a file called `.env` 

- AUTH_URL
- CLIENT_ID
- REDIRECT_URL
- SCOPE
- CLIENT_SECRET

in addition, will need to set

- JWT_SECRET

To a secret for us to sign our own outgoing JWT that we create


If you dont have the `.env` file present, then `bun backend` wont build

# Using Bun for dev #

`bun install`

sets up tailwind / daisy UI etc

`bun tailwind` runs a watcher on the CSS, and generates tailwind output on the fly

`bun backend` runs a watcher on the Zig code, recompiles and relaunches on demand

# Just plain build #

`zig build`

`zig build run`
