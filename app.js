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

    sendTextMessage(senderID, "Quick reply tapped");
    return;
  }

  if (messageText) {

    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (messageText) {
      case 'image':
        sendImageMessage(senderID);
        break;

      case 'gif':
        sendGifMessage(senderID);
        break;

      case 'audio':
        sendAudioMessage(senderID);
        break;

      case 'video':
        sendVideoMessage(senderID);
        break;

      case 'file':
        sendFileMessage(senderID);
        break;

      case 'button':
        sendButtonMessage(senderID);
        break;

      case 'generic':
        sendGenericMessage(senderID);
        break;

      case 'receipt':
        sendReceiptMessage(senderID);
        break;

      case 'quick reply':
        sendQuickReply(senderID);
        break;        

      case 'read receipt':
        sendReadReceipt(senderID);
        break;        

      case 'typing on':
        sendTypingOn(senderID);
        break;        

      case 'typing off':
        sendTypingOff(senderID);
        break;        

      case 'account linking':
        sendAccountLinking(senderID);
        break;

      default:
        sendTextMessage(senderID, messageText);
    }
  } else if (messageAttachments) {
    sendTextMessage(senderID, "Message with attachment received");
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

  // When a postback is called, we'll send a message back to the sender to 
  // let them know it was successful
  sendTextMessage(senderID, "Postback called");
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
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Gif using the Send API.
 *
 */
function sendGifMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/instagram_logo.gif"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send audio using the Send API.
 *
 */
function sendAudioMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "audio",
        payload: {
          url: SERVER_URL + "/assets/sample.mp3"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a video using the Send API.
 *
 */
function sendVideoMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "video",
        payload: {
          url: SERVER_URL + "/assets/allofus480.mov"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a file using the Send API.
 *
 */
function sendFileMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "file",
        payload: {
          url: SERVER_URL + "/assets/test.txt"
        }
      }
    }
  };

  callSendAPI(messageData);
}

function getRandomFact() {
  var facts = [
    "Every year, nearly four million cats are eaten in Asia",
    "On average, cats spend 2/3 of every day sleeping",
    "Unlike dogs, cats do not have a sweet tooth",
    "When a cat chases its prey, it keeps its head level",
    "The technical term for a cat's hairball is a bezoar",
    "A group of cats is called a clowder",
    "Female cats tend to be right pawed, while male cats are more often left pawed",
    "A cat cannot climb head first down a tree because its claws are curved the wrong way",
    "Cats make about 100 different sounds",
    "A cat's brain is biologically more similar to a human brain than it is to a dog's",
    "There are more than 500 million domestic cats in the world",
    "Approximately 24 cat skins can make a coat",
    "During the Middle Ages, cats were associated with witchcraft",
    "Cats are the most popular pet in North American Cats are North America's most popular pets",
    "Approximately 40,000 people are bitten by cats in the U.S.",
    "A cat's hearing is better than a dog's",
    "A cat can travel at a top speed of approximately 31 mph (49 km) over a short distance",
    "A cat can jump up to five times its own height in a single bound",
    "Some cats have survived falls of over 20 meters",
    "Researchers are unsure exactly how a cat purrs",
    "When a family cat died in ancient Egypt, family members would mourn by shaving off their eyebrows",
    "In 1888, more than 300,000 mummified cats were found an Egyptian cemetery",
    "Most cats give birth to a litter of between one and nine kittens",
    "Smuggling a cat out of ancient Egypt was punishable by death",
    "The earliest ancestor of the modern cat lived about 30 million years ago",
    "The biggest wildcat today is the Siberian Tiger",
    "The smallest wildcat today is the Black-footed cat",
    "Many Egyptians worshipped the goddess Bast, who had a woman's body and a cat's head",
    "Mohammed loved cats and reportedly his favorite cat, Muezza, was a tabby",
    "The smallest pedigreed cat is a Singapura, which can weigh just 4 lbs",
    "Cats hate the water because their fur does not insulate well when it's wet",
    "The Egyptian Mau is probably the oldest breed of cat",
    "A cat usually has about 12 whiskers on each side of its face",
    "A cat's eyesight is both better and worse than humans",
    "A cat's jaw can't move sideways, so a cat can't chew large chunks of food",
    "A cat almost never meows at another cat, mostly just humans",
    "A cat's back is extremely flexible because it has up to 53 loosely fitting vertebrae",
    "Many cat owners think their cats can read their minds",
    "Two members of the cat family are distinct from all others: the clouded leopard and the cheetah",
    "In Japan, cats are thought to have the power to turn into super spirits when they die",
    "Most cats had short hair until about 100 years ago, when it became fashionable to own cats and experiment with breeding",
    "Cats have 32 muscles that control the outer ear",
    "Cats have about 20,155 hairs per square centimeter",
    "The first cat show was organized in 1871 in London",
    "A cat has 230 bones in its body",
    "Foods that should not be given to cats include onions, garlic, green tomatoes, raw potatoes, chocolate, grapes, and raisins",
    "A cat's heart beats nearly twice as fast as a human heart",
    "Cats spend nearly 1/3 of their waking hours cleaning themselves",
    "Grown cats have 30 teeth",
    "The largest cat breed is the Ragdoll",
    "Cats are extremely sensitive to vibrations",
    "The cat who holds the record for the longest non-fatal fall is Andy",
    "The richest cat is Blackie who was left £15 million by his owner, Ben Rea",
    "Around the world, cats take a break to nap —a catnap— 425 million times a day",
    "In homes with more than one cat, it is best to have cats of the opposite sex. They tend to be better housemates.",
    "Cats are unable to detect sweetness in anything they taste",
    "Perhaps the oldest cat breed on record is the Egyptian Mau, which is also the Egyptian language's word for cat",
    "In one litter of kittens, there could be multiple father cats",
    "Teeth of cats are sharper when they're kittens. After six months, they lose their needle-sharp milk teeth",
    "Collectively, kittens yawn about 200 million time per hour",
    "According to the International Species Information Service, there are only three Marbled Cats still in existence worldwide.  One lives in the United States.",
    "Cats show affection and mark their territory by rubbing on people. Glands on their face, tail and paws release a scent to make its mark",
    "Maine Coons are the most massive breed of house cats. They can weigh up to around 24 pounds",
    "If you killed a cat in the ages of Pharaoh, you could've been put to death",
    "Most cats will eat 7 to 20 small meals a day. This interesting fact is brought to you by Nature's Recipe®",
    "Most cats don't have eyelashes",
    "Call them wide-eyes: cats are the mammals with the largest eyes",
    "Cats who eat too much tuna can become addicted, which can actually cause a Vitamin E deficiency",
    "Cats can pick up on your tone of voice, so sweet-talking to your cat has more of an impact than you think",
    "Some cats can survive falls from as high up as 65 feet or more",
    "Genetically, cats' brains are more similar to that of a human than a dog's brain",
    "If your cat's eyes are closed, it's not necessarily because it's tired. A sign of closed eyes means your cat is happy or pleased",
    "Cats CAN be lefties and righties, just like us. More than forty percent of them are, leaving some ambidextrous",
    "Cats have the skillset that makes them able to learn how to use a toilet",
    "Each side of a cat's face has about 12 whiskers",
    "Landing on all fours is something typical to cats thanks to the help of their eyes and special balance organs in their inner ear. These tools help them straighten themselves in the air and land upright on the ground.",
    "Eating grass rids a cats' system of any fur and helps with digestion",
    "Cats have 24 more bones than humans",
    "Black cats aren't an omen of ill fortune in all cultures. In the UK and Australia, spotting a black cat is good luck",
    "The Maine Coon is appropriately the official State cat of its namesake state",
    "The world's most fertile cat, whose name was Dusty, gave birth to 420 kittens in her lifetime",
    "Sometimes called the Canadian Hairless, the Sphynx is the first cat breed that has lasted this long—the breed has been around since 1966",
    "Sir Isaac Newton, among his many achievements, invented the cat flap door",
    "In North America, cats are a more popular pet than dogs. Nearly 73 million cats and 63 million dogs are kept as household pets",
    "Today, cats are living twice as long as they did just 50 years ago",
    "Outdoor cats' lifespan averages at about 3 to 5 years; indoor cats have lives that last 16 years or more",
    "Cats have the cognitive ability to sense a human's feelings and overall mood",
    "Cats prefer their food at room temperature—not too hot, not too cold",
    "Bobtails are known to have notably short tails -- about half or a third the size of the average cat",
    "A fingerprint is to a human as a nose is to a cat",
    "Cats have over 100 sounds in their vocal repertoire, while dogs only have 10",
    "Cats came to the Americas from Europe as pest controllers in the 1750s",
    "According to the Association for Pet Obesity Prevention (APOP), about 50 million of our cats are overweight",
    "Cats use their whiskers to measure openings, indicate mood and general navigation",
    "Blue-eyed cats have a high tendency to be deaf, but not all cats with blue eyes are deaf",
    "Ancient Egyptians first adored cats for their finesse in killing rodents—as far back as 4,000 years ago",
    "The color of York Chocolates becomes richer with age. Kittens are born with a lighter coat than the adults",
    "Because of widespread cat smuggling in ancient Egypt, the exportation of cats was a crime punishable by death",
    "Cats actually have dreams, just like us. They start dreaming when they reach a week old",
    "It is important to include fat in your cat's diet because they're unable to make the nutrient in their bodies on their own",
    "A cat's field of vision does not cover the area right under its nose",
    "Talk about Facetime: Cats greet one another by rubbing their noses together",
    "Cats sleep 16 hours of any given day",
    "Although it is known to be the tailless cat, the Manx can be born with a stub or a short tail",
    "A Selkirk slowly loses its naturally-born curly coat, but it grows again when the cat is around 8 months",
    "A cat's heart beats almost double the rate of a human heart, from 110 to 140 beats per minute",
    "Ragdoll cats live up to their name: they will literally go limp, with relaxed muscles, when lifted by a human",
    "Unlike most other cats, the Turkish Van breed has a water-resistant coat and enjoys being in water",
    "Webbed feet on a cat? The Peterbald's got 'em! They make it easy for the cat to get a good grip on things with skill",
    "Despite appearing like a wild cat, the Ocicat does not have an ounce of wild blood",
    "Cat's back claws aren't as sharp as the claws on their front paws",
    "A group of kittens is called a kindle, and clowder is a term that refers to a group of adult cats",
    "A third of cats' time spent awake is usually spent cleaning themselves",
    "A female cat is also known to be called a queen or a molly",
    "Want to call a hairball by its scientific name? Next time, say the word bezoar",
    "Cats have a 5 toes on their front paws and 4 on each back paw",
    "In multi-pet households, cats are able to get along especially well with dogs if they're introduced when the cat is under 6 months old and the dog is under one year old",
    "Twenty-five percent of cat owners use a blow drier on their cats after bathing",
    "Rather than nine months, cats' pregnancies last about nine weeks",
    "It has been said that the Ukrainian Levkoy has the appearance of a dog, due to the angles of its face",
    "A cat can reach up to five times its own height per jump",
    "Cats have a strong aversion to anything citrus",
    "Cats would rather starve themselves than eat something they don't like. This means they will refuse an unpalatable -- but nutritionally complete -- food for a prolonged period",
    "The Snow Leopard, a variety of the California Spangled Cat, always has blue eyes",
    "The two outer layers of a cat's hair are called, respectively, the guard hair and the awn hair",
    "When a household cat died in ancient Egypt, its owners showed their grief by shaving their eyebrows",
    "Caution during Christmas: poinsettias may be festive, but they’re poisonous to cats",
    "Most kittens are born with blue eyes, which then turn color with age",
    "A cat's meow is usually not directed at another cat, but at a human. To communicate with other cats, they will usually hiss, purr and spit.",
    "According to the Guinness World Records, the largest domestic cat litter totaled at 19 kittens, four of them stillborn",
    "As temperatures rise, so do the number of cats. Cats are known to breed in warm weather, which leads many animal advocates worried about the plight of cats under Global Warming.",
    "Cats' rough tongues enable them to clean themselves efficiently and to lick clean an animal bone",
    "Most cat litters contain four to six kittens"
  ];

  var randomnumber = Math.floor(Math.random() * ((facts.length - 1) - 0 + 1)) + 0;

  return facts[randomnumber];

}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: getRandomFact(),
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPER_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",               
            image_url: SERVER_URL + "/assets/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",               
            image_url: SERVER_URL + "/assets/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",        
          timestamp: "1428444852", 
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
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
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
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

