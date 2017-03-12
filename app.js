/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

// Time Delay variable
var delayMills = 1000;

/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

console.log("validation token " + VALIDATION_TOKEN + " PAGE_ACCESS_TOKEN : " + PAGE_ACCESS_TOKEN);

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});

/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

    receivedQuickReplyPostback(event);
    return;
  }

  if (messageText) {
    messageText = messageText.toLowerCase();
    console.log("swith case text: " + messageText);
    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (messageText) {    

      case 'today\'s special':
        sendTypingOn(senderID);
        sendAllSpecial(senderID);
      break;

      case 'todays special':
        sendTypingOn(senderID);
        sendAllSpecial(senderID);        
      break;  

      case 'menu':
        sendTypingOn(senderID);
        sendMainMenu(senderID);
      break;

      case 'special':
        sendTypingOn(senderID);
        sendAllSpecial(senderID);
        break;

      case 'special dishes':
        sendTypingOn(senderID);
        sendAllSpecial(senderID);
        break;        

      case 'party':
        sendTypingOn(senderID);
        sendPartySpecial(senderID);
        break;        

      case 'party special':
        sendTypingOn(senderID);
        sendPartySpecial(senderID);
        break;       

      case 'opening hours':
        sendTypingOn(senderID);
        sendOpeningHoursText(senderID);
      break;   

      case 'gallery':
        /*sendTypingOn(senderID);
        showGallery(senderID);*/
      break;

      case 'reviews':

      break;      

      case 'hungry':
        
      break;
 
      default:
        sendTypingOn(senderID);
        sendWelcomeMessage(senderID);

        setTimeout(function(){    
            greetText(senderID);
          },delayMills);     
    }
  } else if (messageAttachments) {
    sendTypingOn(senderID);
    sendWelcomeMessage(senderID);
    /*setTimeout(function(){    
      sendQuickReplySpecial(senderID);
    },delayMills);*/
  }
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Quick Reply Postback Event
 *
 * This event is called when a postback is tapped on a Quick Reply. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */

function receivedQuickReplyPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;
  var message = event.message;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var quickReply = message.quick_reply;
  var payload = quickReply.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

   if (payload) {
    // If we receive a text payload, check to see if it matches any special
    switch (payload) {
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_ALL_SPECIAL':
          sendTypingOn(senderID);
          sendAllSpecial(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_DAILY_SPECIAL':
          sendTypingOn(senderID);
          sendDailySpecial(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_PARTY_SPECIAL':
          sendTypingOn(senderID);
          sendPartySpecial(senderID);
        case 'DEVELOPER_DEFINED_PAYLOAD_REVIEWS':
          showReviews(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_TESTIMONALS':
          showTestimonials(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_START_OVER':
          sendTypingOn(senderID);
          sendWelcomeMessage(senderID);
        break;        
        default:
        sendTypingOn(senderID);
        sendWelcomeMessage(senderID);
    }
   }else{
        sendTypingOn(senderID);
        sendWelcomeMessage(senderID);
   }
}

/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

   if (payload) {
    // If we receive a text payload, check to see if it matches any special
    switch (payload) {
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_MENU':
          sendTypingOn(senderID);
          sendMainMenu(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_LOCATION':
          sendTypingOn(senderID);
          sendLocationTemplate(senderID);

          setTimeout(function(){    
            sendQuickReplySpecial(senderID);
          },delayMills);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_OPENING_HOURS':
          sendTypingOn(senderID);
          sendOpeningHoursText(senderID);

          setTimeout(function(){    
            sendQuickReplySpecial(senderID);
          },delayMills);
          break;
        case 'GET_STARTED_BUTTON_PAYLOAD':
          console.log("Received postback for get started button");
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_ALL_SPECIAL':
          sendTypingOn(senderID);
          sendAllSpecial(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_DAILY_SPECIAL':
          sendTypingOn(senderID);
          sendDailySpecial(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_PARTY_SPECIAL':
          sendTypingOn(senderID);
          sendPartySpecial(senderID);
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_ALL_SPECIAL_BACK':          
          sendQuickRepliesActions(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_DAILY_SPECIAL_BACK':
          sendQuickRepliesActions(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_PARTY_SPECIAL_BACK':
          sendQuickRepliesActions(senderID);
        break;
        case 'DEVELOPER_DEFINED_PAYLOAD_FOR_MAIN_MENU_BACK':        
            sendQuickReplySpecial(senderID);
        break;
        default:
        sendTypingOn(senderID);
        sendWelcomeMessage(senderID);
    }
   }else{
        sendTypingOn(senderID);
        sendWelcomeMessage(senderID);
   } 

}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 * 
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendWelcomeMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {        
      attachment:{
        type:"template",
        payload:{
          template_type:"generic",
          elements:[
             {
              title:"Welcome to Famous Greek ",
              image_url:"https://www.famousgreeksalads.com/_upload/slideshow/13401481191902759378.jpg",
              subtitle:"Try Delicious Food",
              default_action: {
                type: "web_url",
                url: "https://www.famousgreeksalads.com",
                messenger_extensions: true,
                webview_height_ratio: "tall",
                fallback_url: "https://www.famousgreeksalads.com"
              },
              buttons:[
                {
                  type:"postback",
                  title:"Menu",
                  payload:"DEVELOPER_DEFINED_PAYLOAD_FOR_MENU"
                },
                {
                  type:"postback",
                  title:"Our Location",
                  payload:"DEVELOPER_DEFINED_PAYLOAD_FOR_LOCATION"
                },
                {
                    type:"postback",
                    title:"Opening Hours",
                    payload:"DEVELOPER_DEFINED_PAYLOAD_FOR_OPENING_HOURS"
                }
                /*,
                {
                  type:"postback",
                  title:"Place An Order",
                  payload:"DEVELOPER_DEFINED_PAYLOAD_PLACE_ORDER"
                }                                
                ,
                {
                  type:"postback",
                  title:"Call",
                  payload:"DEVELOPER_DEFINED_PAYLOAD_FOR_CALL"
                }  */            
              ]      
            }
          ]
        }    
      }
    }
  };

  callSendAPI(messageData);
}

// This send main menu
function sendMainMenu(recipientId){

  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {        
      attachment:{
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "Family Meals",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Family-Meals/c=5864/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401483603012685235.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Family-Meals/c=5864/clear/",
              title: "Checkout"
            },{
              type:"phone_number",
              title:"Call",
              payload:"+17277974998"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_MAIN_MENU_BACK",
              title: "Back"
            }],
          }, {
            title: "Soups & Starters",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Soups-and-Starters/c=1518/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Soups-and-Starters/c=1518/clear/",
              title: "Checkout"
            },{
              type:"phone_number",
              title:"Call",
              payload:"+17277974998"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_MAIN_MENU_BACK",
              title: "Back"
            }]
          },{
            title: "Salads",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Salads/c=1519/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Salads/c=1519/clear/",
              title: "Checkout"
            },{
              type:"phone_number",
              title:"Call",
              payload:"+17277974998"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_MAIN_MENU_BACK",
              title: "Back"
            }]
          },{
            title: "Party Salads",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Party-Salads/c=1587/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Party-Salads/c=1587/clear/",
              title: "Checkout"
            },{
              type:"phone_number",
              title:"Call",
              payload:"+17277974998"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_MAIN_MENU_BACK",
              title: "Back"
            }]
          },{
            title: "Party Platters",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Party-Platters/c=2761/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Party-Platters/c=2761/clear/",
              title: "Checkout"
            },{
              type:"phone_number",
              title:"Call",
              payload:"+17277974998"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_MAIN_MENU_BACK",
              title: "Back"
            }]
          },{
            title: "Beverages",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Beverages/c=1526/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Beverages/c=1526/clear/",
              title: "Checkout"
            },{
              type:"phone_number",
              title:"Call",
              payload:"+17277974998"
            },
            {
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_MAIN_MENU_BACK",
              title: "Back"
            }]
          }]
        }
      }
    }    
  };

  callSendAPI(messageData);
}

function sendLocationTemplate(recipientId){
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment:{
        type:"template",
        payload:{
          template_type: "generic",
          elements:[
          {
            title:"Famous Greek Salads",
            image_url:"https://maps.googleapis.com/maps/api/staticmap?center=28.0123703,-82.7125298&markers=color:red%7Clabel:C%7C28.012431,-82.7138837&zoom=16&size=600x400&key=AIzaSyBJqqGGwS1HthhCLL1HC8F5AcUeMu6eQVs",
            item_url:"https://www.google.co.in/maps/place/Famous+Greek+Salads/@28.012431,-82.7138837,17z/data=!3m1!4b1!4m5!3m4!1s0x88c2ee75f53b20b9:0xdeb12856e08e448d!8m2!3d28.012431!4d-82.711695"    
          }
          ]
        }
      }
    }
  };   
  callSendAPI(messageData);
}

function sendOpeningHoursText(recipientId){
  var messageData = {
    recipient: {
      id: recipientId
    },message:{
      text:"RESTAURANT HOURS\nSunday 11:00AM - 04:00PM\nMonday thru Saturday 11:00AM - 08:30PM"
    }
  };

  callSendAPI(messageData);
}

function sendQuickReplySpecial(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "Checkout our most appreciated dishes by our customer's",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Special Dishes",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_ALL_SPECIAL"
        },
        {
          "content_type":"text",
          "title":"Daily Special",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_DAILY_SPECIAL"
        },
        {
          "content_type":"text",
          "title":"Party Special",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PARTY_SPECIAL"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

function sendAllSpecial(recipientId){

  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {        
      attachment:{
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "1/4 Greek Chicken",
            subtitle: "Marinated and baked crisp with oregano and lemon served with a side Greek salad and choice of Greek potatoes or rice.",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Famous-Favorites/c=6239/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401483603012685235.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Famous-Favorites/c=6239/clear/",
              title: "Checkout"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_ALL_SPECIAL_BACK",
              title: "Back"
            }],
          }, {
            title: "Famous Greek Combo",
            subtitle:"Choice of Grilled Chicken or Sliced Gyro over rice with a side Greek salad and choice of any Famous Spread with pita!",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Famous-Favorites/c=6239/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Famous-Favorites/c=6239/clear/",
              title: "Checkout"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_ALL_SPECIAL_BACK",
              title: "Back"
            }]
          },{
            title: "Moussaka",
            subtitle:"Layers of eggplant, ground beef, and a creamy bechamel with a hint of cinnamon. Served with a side Greek salad!",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Famous-Favorites/c=6239/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Famous-Favorites/c=6239/clear/",
              title: "Checkout"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_ALL_SPECIAL_BACK",
              title: "Back"
            }]
          }]
        }
      }
    }    
  };

  callSendAPI(messageData);
}


function sendDailySpecial(recipientId){

  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {        
      attachment:{
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "Family Meal for 4 - Grilled Chicken with Rice!",
            subtitle:"Choice of sliced gyro or grilled chicken, a family size Greek salad, and tzatziki or hummus with pita!",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Family-Meals/c=5864/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401483603012685235.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Family-Meals/c=5864/clear/",
              title: "Checkout"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_DAILY_SPECIAL_BACK",
              title: "Back"
            }],
          }, {
            title: "Family Meal for 4 - Subs and Pitas",
            subtitle:"A great selection of our Famous sandwiches with a family size Greek salad!",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Family-Meals/c=5864/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Family-Meals/c=5864/clear/",
              title: "Checkout"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_DAILY_SPECIAL_BACK",
              title: "Back"
            }]
          },{
            title: "Family Meal for 6 - Grilled Chicken with Rice!",
            subtitle:"Choice of grilled chicken or sliced gyro, a family size Greek salad, and choice of tzatziki or hummus with pita!",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Family-Meals/c=5864/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Family-Meals/c=5864/clear/",
              title: "Checkout"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_DAILY_SPECIAL_BACK",
              title: "Back"
            }]
          }]
        }
      }
    }    
  };

  callSendAPI(messageData);
}

function sendPartySpecial(recipientId){

  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {        
      attachment:{
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "Chicken Souvlaki Or Gyro Platter",
            subtitle:"This platter gives your guests a chance to build their own gyro with the pita, lettuce, tomato, onion, and tzatziki sauce all separate.",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Party-Platters/c=2761/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401483603012685235.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Party-Platters/c=2761/clear/",
              title: "Checkout"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_PARTY_SPECIAL_BACK",
              title: "Back"
            }],
          }, {
            title: "Deli Wrap Tray",
            subtitle:"Our wraps our prepared on tomato basil and spinach tortillas. Choose up to 3 options!",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Party-Platters/c=2761/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Party-Platters/c=2761/clear/",
              title: "Checkout"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_PARTY_SPECIAL_BACK",
              title: "Back"
            }]
          },{
            title: "Famous Cubans Tray",
            subtitle:"Always a party favorite!",
            item_url: "https://www.famousgreeksalads.com/order-food-online/Party-Platters/c=2761/clear/",               
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
            buttons: [{
              type: "web_url",
              url: "https://www.famousgreeksalads.com/order-food-online/Party-Platters/c=2761/clear/",
              title: "Checkout"
            },{
              type: "postback",
              payload: "DEVELOPER_DEFINED_PAYLOAD_FOR_PARTY_SPECIAL_BACK",
              title: "Back"
            }]
          }]
        }
      }
    }    
  };

  callSendAPI(messageData);
}

function sendQuickRepliesActions(recipientId){
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "Get Connected with us...",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Testimonials",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_TESTIMONALS"      
        },
        {
          "content_type":"text",
          "title":"Reviews",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_REVIEWS"
        },
        {
          "content_type":"text",
          "title":"Start Over",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_START_OVER"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

function showTestimonials(recipientId){
  var messageData = {
    recipient: {
      id: recipientId
    },message:{
      text:"Famous Greek Salads offers fresh and healthy Greek food at reasonable prices. Catering Available."
    }
  };

  callSendAPI(messageData);
}

function showReviews(recipientId){
  /*var messageData = {
    recipient: {
      id: recipientId
    },
    message: {        
      attachment:{
        type: "template",
        payload: {
          template_type: "list",
          top_element_style: "com",
          elements: [{
            title: "Christina R.",
            subtitle:"This place gets busy! And it seems like there are some repeat customers because the waitress (the only waitress working) knew people's names. The waitress was FAST, efficient, patient, she was great for handling all of those tables. She was so chipper and happy too. The food was spot on, there is a reason why 'famous' is in the name of their restaurant. You can sit inside or outside where there are tables out front. I've seen people bring their dogs with them to sit outside too. The entire staff is nice, even the nice guy that brings the food out. They do take out, and deliver ($50 min I believe).",
            item_url: "https://www.yelp.com/biz/famous-greek-salads-clearwater"
          },{
            title: "Kyle P.",
            subtitle:"I used to eat here two times a week and man do I miss it. We have since moved and I have not found a Greek restaurant that compares. Mike and Mike Jr. both have great personal service.  You can tell that they take pride in their food and care about your personal experience with them.  Highly recommend this place!",
            item_url: "https://www.yelp.com/biz/famous-greek-salads-clearwater"
          },{
            title: "Bill K.",
            subtitle:"The Moussaka is just amazing!! Coupled with the Greek Salad that accompanies it- you have a meal you just can't beat!  Really like this quaint little place and all its amazing menu items!",
            item_url: "https://www.yelp.com/biz/famous-greek-salads-clearwater"
          },{
            title: "Tori B.",
            subtitle:"No Complaints from this girl.  We order from here at least twice a month the food is always fresh and hot.  The online ordering system is easy to navigate and customizable for  people like me who can never order an item as it comes. I always have to change something and the online system lets me do that.\nThe 1/4 chicken is always crispy and juicy at the same time , the mini Greek salad is more than enough to fill me up.  Spanikopita oh how I love thee crispy and full of flavor. The potato salad is always flavorful and never bland perfect blend of spices.",
            item_url: "https://www.yelp.com/biz/famous-greek-salads-clearwater"
          }]
        }
      }
    }    
  };

  callSendAPI(messageData);*/
}

function greetText(recipientId){
  var messageData = {
    recipient: {
      id: recipientId
    },message:{
      text:"Hi, We'r happy to see u.."
    }
  };

  callSendAPI(messageData);
}

function showGallery(recipientId){
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {        
      attachment:{
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "",
            subtitle:"",
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401483603012685235.jpg",
          }, {
            title: "",
            subtitle:"",
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
          },{
            title: "",
            subtitle:"",
            image_url: "https://www.famousgreeksalads.com/_upload/slideshow/13401465644405939908.jpg",
          }]
        }
      }
    }    
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}


/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;






















