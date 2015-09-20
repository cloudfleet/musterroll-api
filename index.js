/* jshint node: true */
"use strict";

var musterroll_api = (function() {

  var express = require('express');
  var _ = require('lodash');
  var passport = require('passport');
  var LocalStrategy = require('passport-local').Strategy;


  var UserAPIServer = function (options) {

      options = options || {};
      var userStore = options.userStore;
      var userStoreInitializer = options.user_store_initializer;

      // better invalidate cookies on server reboot than having an insecure default
      var cookieSecret = options.cookie_secret || Math.random().toString(36).slice(2);

      var webServer = options.server || express();

      webServer.use(express.cookieParser(cookieSecret));
      webServer.use(express.cookieSession());
      webServer.use(express.bodyParser());
      webServer.use(passport.initialize());
      webServer.use(passport.session());


      var sanitizeIncomingUserData = function (user_data) {
        return _.pick(user_data, 'id', 'aliases', 'firstname', 'lastname');
      };

      var sanitizeOutgoingUserData = function (user_data) {
        return _.pick(user_data, 'id', 'aliases', 'firstname', 'lastname', 'isAdmin');
      };

      var getUserForAlias = function (alias) {
        _.find(userStore.getUsers(), function (user) {
          return user.id === alias || (user.aliases && _.includes(user.aliases, alias));
        });
      };

      var userIdAvailable = function (user_id) {
        return !getUserForAlias(user_id);
      };

      var isAuthenticated = function (req, res, next) {
          if(req.isAuthenticated())
          {
              next();
          }
          else
          {
              res.status(401).send('Not authenticated');
          }
      };

      var isAdmin = function (req, res, next) {
          if(req.isAuthenticated() && req.user.isAdmin)
          {
              next();
          }
          else
          {
              res.status(401).send('Not authenticated');
          }
      };

      var isAdminOrSelf = function(req, res, next)
      {
        var user_id = req.param('user_id');
        if(user_id === req.user.id)
        {
          next();
        }
        else
        {
          isAdmin(req, res, next);
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
            if(!req.query.user || (req.query.user === user.id))
            {
              var body = JSON.stringify(sanitizeOutgoingUserData(user));
              res.setHeader('Content-Type', 'application/json');
              res.setHeader('X-Authenticated-User', user.id);
              res.setHeader('X-Authenticated-User-Admin', user.isAdmin);
              res.end(body);
            }
            else {
              res.status(403).send('Forbidden');
            }
          }
          else
          {
              res.status(401).send('Authentication Needed');
          }
      });

      webServer.post('/login', passport.authenticate('local'), function(req, res){
          res.end('{"success": true}');
      });

      webServer.get('/api/v1/users', isAdmin, function(req, res){
          var body = JSON.stringify(_.map(_.values(userStore.getUsers()), sanitizeOutgoingUserData));
          res.setHeader('Content-Type', 'application/json');
          res.end(body);
      });
      webServer.get('/api/v1/users/from_alias/:alias', function(){return true;}, function(req, res) {
          var alias = req.param('alias');
          var user_candidate = getUserForAlias(alias);
          if(user_candidate)
          {
            var body = JSON.stringify(sanitizeOutgoingUserData(userStore.getUsers()[req.param('user_id')]));
            res.setHeader('Content-Type', 'application/json');
            res.end(body);
          }
          else {
            res.status(404).send('User not found');
          }
      });
      webServer.get('/api/v1/users/:user_id', isAdminOrSelf, function(req, res){
          var body = JSON.stringify(userStore.getUsers()[req.param('user_id')]);
          res.setHeader('Content-Type', 'application/json');
          res.end(body);
      });
      webServer.post('/api/v1/users', isAdmin, function(req, res){
          var client_user = sanitizeIncomingUserData(req.body);
          var user_id = client_user.id;
          if(!user_id)
          {
            res.status(400).send('User must have non-empty user id');
          }
          else if(userIdAvailable(user_id))
          {
            res.status(409).send('User ID already taken. Might be an alias.');
          }
          else
          {
            userStore.updateUser(client_user);

            var body = JSON.stringify(sanitizeOutgoingUserData(client_user));

            res.setHeader('Content-Type', 'application/json');
            res.end(body);
          }
      });
      webServer.put('/api/v1/users/:user_id', isAdminOrSelf, function(req, res){
          var user_id = req.param('user_id');
          var client_user = sanitizeIncomingUserData(req.body);
          var server_user = userStore.getUsers()[user_id];

          var merged_user = _.defaults(client_user, server_user);
          userStore.updateUser(merged_user);

          var body = JSON.stringify(client_user);

          res.setHeader('Content-Type', 'application/json');
          res.end(body);
      });
      webServer.delete('/api/v1/users/:user_id', isAdmin, function(req, res){
          var user_id = req.param('user_id');
          userStore.deleteUser(user_id);

          var body = JSON.stringify({success: true});

          res.setHeader('Content-Type', 'application/json');
          res.end(body);
      });
      webServer.put('/api/v1/users/:user_id/password', isAdminOrSelf, function(req, res){
          var user_id = req.param('user_id');
          var password = req.body.password;
          userStore.setPassword(user_id, password);

          var body = JSON.stringify({success: true});

          res.setHeader('Content-Type', 'application/json');
          res.end(body);
      });

      webServer.get('/logout', function(req, res){
        req.logout();
        var body = JSON.stringify({success: true});
        res.setHeader('Content-Type', 'application/json');
        res.end(body);
      });


      this.userApiServer = webServer;
  };

  return {
     createServer: function(options){return new UserAPIServer(options);}
  };
}());

module.exports = {
    createServer: musterroll_api.createServer
};
