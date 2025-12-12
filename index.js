require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const admin = require("firebase-admin");
const port = process.env.PORT || 5555;
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString(
  "utf-8"
);
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
// middleware
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:5174",
      process.env.CLIENT_DOMAIN,
    ],
    credentials: true,
    optionSuccessStatus: 200,
  })
);
app.use(express.json());

// jwt middlewares
const verifyJWT = async (req, res, next) => {
  const token = req?.headers?.authorization?.split(" ")[1];
  console.log(token);
  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    console.log(decoded);
    next();
  } catch (err) {
    console.log(err);
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // garmentsDB.products
    const db = client.db("garmentsDB");
    const productsCollection = db.collection("products");
    const ordersCollection = db.collection("orders");

    //////////////////////////////////////////////////////
    // POST All Products

    app.post("/products", async (req, res) => {
      const productData = req.body;
      // console.log(productData);
      const result = await productsCollection.insertOne(productData);
      res.send(result);
    });

    // GET all Products

    app.get("/products", async (req, res) => {
      const result = await productsCollection.find().toArray();
      res.send(result);
    });

    // GET Single Product

    app.get("/product/:id", async (req, res) => {
      const id = req.params.id;
      const result = await productsCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });
    //////////////////////////////////////////////////////

    // Payment endpoints
    app.post("/create-checkout-session", async (req, res) => {
      const paymentInfo = req.body;
            // console.log(paymentInfo);
            // return
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: {
                name: paymentInfo?.name,
                description: paymentInfo?.description,
                images: [paymentInfo?.images[0]],
              },
              unit_amount: paymentInfo?.unitPrice * 100,
            },
            // adjustable_quantity for multiple quantity
            adjustable_quantity: {
              enabled: true,
              minimum: paymentInfo?.minimum,
              maximum: paymentInfo?.maximum,
            },
            quantity: paymentInfo?.orderQuantity,
          },
        ],
        customer_email: paymentInfo?.customer?.email,
        mode: "payment",
        metadata: {
          productId: paymentInfo?.productId,
          customer: paymentInfo?.customer.email,
          manager: paymentInfo?.manager.email,
          orderQuantity: paymentInfo?.orderQuantity,
        },

        success_url: `${process.env.CLIENT_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.CLIENT_DOMAIN}/product/${paymentInfo?.productId}`,
      });
      // console.log("session URL:----->", session.url);
      // console.log("session :----->", session);
      res.send({ url: session.url });
    });

    app.post("/payment-success", async (req, res) => {
      const { sessionId } = req.body;
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      // console.log("-------Session-------------: ", session);
      // return;
      const product = await productsCollection.findOne({
        _id: new ObjectId(session.metadata.productId),
      });
      // console.log(product); return
      // const order = await ordersCollection.findOne({
      //   transactionId: session.payment_intent,
      // });

      if (session.status === "complete" ) {
        // save order data in db
        const orderInfo = {
          productId: session.metadata.productId,
          transactionId: session.payment_intent,
          customer: session.metadata.customer,
          status: "pending", // session.metadata.status = value is *complete*
          manager: product?.manager,
          name: product?.title,
          category: product?.category,
          quantity: Number(session.metadata.orderQuantity),
          price: session.amount_total / 100,
          image: product?.images[0],
          // country: session.customer_details.country,
        };
        // console.log(orderInfo);return 
        const result = await ordersCollection.insertOne(orderInfo);
        // update product quantity
        const quantity = Number(result.quantity)
        await productsCollection.updateOne(
          {
            _id: new ObjectId(session.metadata.productId),
          },
          { $inc: { quantity: -quantity } }
        );

        return res.send({
          transactionId: session.payment_intent,
          orderId: result.insertedId,
        });
      }
      res.send(
        res.send({
          transactionId: session.payment_intent,
          orderId: order._id,
        })
      );
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("TailorFlow Server is talking..");
});

app.listen(port, () => {
  console.log(`TailorFlow Server is running on port ${port}`);
});
