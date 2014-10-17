var express = require('express');
var _ = require('lodash');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;


var UserAPIServer = function(options)
{
    options = options || {};
    var userStore = options["userStore"];
    var userStoreInitializer = options["user_store_initializer"];

    // better invalidate cookies on server reboot than having an insecure default
    var cookieSecret = options["cookie_secret"] || Math.random().toString(36).slice(2);

    var webServer = options["server"] || express();

    webServer.use(express.cookieParser(cookieSecret));
    webServer.use(express.cookieSession());
    webServer.use(express.bodyParser());
    webServer.use(passport.initialize());
    webServer.use(passport.session());

    var isAuthenticated = function(req, res, next)
    {
        if(req.isAuthenticated())
        {
            next();
        }
        else
        {
            res.status(401).send('Not authenticated');
        }
    };

    var isAdmin = function(req, res, next)
    {
        if(req.isAuthenticated() && req.user.isAdmin)
        {
            next();
        }
        else
        {
            res.status(401).send('Not authenticated');
        }
    };


    passport.use(new LocalStrategy(
        function(username, password, done) {

            if(userStore.isInitialized())
            {

                if(userStore.authorize(username, password))
                {
                    done(null, userStore.getUsers()[username]);
                }
                else
                {
                    done(null, false, { message: 'Incorrect credentials.' });
                }
            }
            else
            {
                userStoreInitializer(
                    username,
                    password,
                    userStore,
                    function(user){
                        done(null, user);
                    },
                    function(){
                        done(null, false, { message: 'Incorrect credentials.' });
                    });
            }
        }
    ));
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
        done(null, userStore.getUsers()[id]);
    });



    webServer.get('/api/v1/currentUser', isAuthenticated, function(req, res){

        var user = req.user;

        if(user)
        {
            var body = JSON.stringify(user);
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Content-Length', body.length);
            res.end(body);
        }
        else
        {
            res.status(404).send('Not found');
        }
    });

    webServer.post('/login', passport.authenticate('local'), function(req, res){
        res.end('{"success": true}');
    });

    webServer.get('/api/v1/users', isAdmin, function(req, res){
        var body = JSON.stringify(_.values(userStore.getUsers()));
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Length', body.length);
        res.end(body);
    });
    webServer.get('/api/v1/users/from_alias/:alias', function(){return true;}, function(req, res) {
        var alias = req.param('alias');
        var user_candidate = _.find(_.values(userStore.getUsers()), function(user) {
            return user.id === alias; // TODO create proper alias handling
        });
    });
    webServer.get('/api/v1/users/:user_id', isAdmin, function(req, res){
        var body = JSON.stringify(userStore.getUsers()[req.param('user_id')]);
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Length', body.length);
        res.end(body);
    });
    webServer.post('/api/v1/users/:user_id', isAdmin, function(req, res){
        var user_id = req.param('user_id');
        var client_user = req.body;
        userStore.updateUser(client_user);

        var body = JSON.stringify(client_user);

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Length', body.length);
        res.end(body);
    });


    this.userApiServer = webServer
};

module.exports = {
    createServer: function(options){
        var server = new UserAPIServer(options);
        return server.userApiServer;
    }
};