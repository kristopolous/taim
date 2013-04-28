# IM that doesn't suck

I'm on a mobile. Meebo sucks, imo.im now sucks ... they all suck.

I want to send a message. I want to receive a message. I don't want to

 * have a video conference
 * talk with friends
 * do anything else

I want a light-weight IM client that can send and receive messages. God damn why is this so hard?!

Fuck, I'll just do it myself.


This was my attempt at doing just that from about 2007.  I intend to bring it up to the new decade
and get it running soon


# Installing

You need `libpurple-dev` `libssl-dev`

Try this:

sudo apt-get install libpurple-dev libssl-dev

# Protocol

After compiling, you start up the server, nullclient. It runs on a port like 19091.  You send it commands:

## uid - a context that has accounts associated with it.
## blist - the buddy list of a context
## user - the username for a context
## pass - the password for a context
## get - the buffer of a context
## send - sending data through a context.

The syntax is generally

<uid> <command> <options>

Except for getting a uid.

So I can do this:

    $ echo uid | nc localhost 19091
    j3TMC9nWYl4
    $

Now I have a base64 handle to use.

    $ echo j3TMC9nWYl4 user someuser | nc localhost 19091

etc ...

In the server window you will eventually see:

    "Account connected: "someuser" (prpl-aim)"

Now you can send things off to it and receive things from it, indefinitely.

