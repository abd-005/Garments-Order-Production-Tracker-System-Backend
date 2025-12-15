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
const crypto = require("crypto");
const serviceAccount = JSON.parse(decoded);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

function generateTrackingId() {
  const prefix = "PRCL"; // your brand prefix
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, ""); // YYYYMMDD
  const random = crypto.randomBytes(3).toString("hex").toUpperCase(); // 6-char random hex

  return `${prefix}-${date}-${random}`;
}
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
    const usersCollection = db.collection("users");
    //////////////////////////////////////////////////////
    //role middleware

    const verifyADMIN = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user?.role !== "admin") {
        return res
          .status(403)
          .send({ message: "Admin only Action!", role: user?.role });
      }
      next();
    };
    const verifyBuyer = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if ((user?.role !== "buyer", user?.status !== "approved")) {
        return res
          .status(403)
          .send({ message: "Buyer only Action!", role: user?.role });
      }
      next();
    };
    const verifyManager = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if ((user?.role !== "manager", user?.status !== "approved")) {
        return res
          .status(403)
          .send({ message: "Manager only Action!", role: user?.role });
      }
      next();
    };

    //////////////////////////////////////////////////////
      ////////////////////////////////////////////////////////////////

    // get a user's role
    app.get("/user/role",verifyJWT, async (req, res) => {
      const result = await usersCollection.findOne({ email: req.tokenEmail });
      res.send({ role: result?.role, status: result?.status });
    });
    // save or update a user in db
    app.post("/user", async (req, res) => {
      const userData = req.body;
      userData.created_at = new Date().toISOString();
      userData.last_loggedIn = new Date().toISOString();
      (userData.status = "pending"),
        (userData.role = "User"),
        (userData.isSuspend = false);
      console.log("From Data: ----> ", userData);

      const query = {
        email: userData.email,
      };

      const alreadyExists = await usersCollection.findOne(query);
      console.log("User Already Exists---> ", !!alreadyExists);

      if (alreadyExists) {
        console.log("Updating user info......");
        const result = await usersCollection.updateOne(query, {
          $set: {
            last_loggedIn: new Date().toISOString(),
          },
        });
        return res.send(result);
      }

      console.log("Saving new user info......");
      const result = await usersCollection.insertOne(userData);
      console.log("\n \n user data: --------> ", userData);
      res.send(result);
    });

    // POST All Products

    app.post("/products",verifyJWT,verifyBuyer, async (req, res) => {
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
    ///////////////////////////CUSTOMER ONLY///////////////////////////

    // GET Single Product

    app.get("/product/:id", verifyJWT, verifyBuyer, async (req, res) => {
      const id = req.params.id;
      const result = await productsCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // Payment endpoints
    app.post("/create-checkout-session", verifyJWT, verifyBuyer,
      async (req, res) => {
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
      }
    );

    app.post("/payment-success", verifyJWT, verifyBuyer, async (req, res) => {
      const { sessionId } = req.body;
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      // console.log("-------Session-------------: ", session);
      // return;
      const product = await productsCollection.findOne({
        _id: new ObjectId(session.metadata.productId),
      });
      // console.log(product); return
      const order = await ordersCollection.findOne({
        transactionId: session.payment_intent,
      });

      if (session.status === "complete" && product && !order) {
        // save order data in db
        const orderInfo = {
          productId: session.metadata.productId,
          transactionId: session.payment_intent,
          customer: session.metadata.customer,
          status: "pending", // session.metadata.status = value is *complete*
          manager: product?.manager,
          name: product?.title,
          category: product?.category,
          quantity: parseInt(session.metadata.orderQuantity),
          price: session.amount_total / 100,
          image: product?.images[0],
          trackingId: generateTrackingId(),
          // country: session.customer_details.country,
        };
        // console.log(orderInfo);return
        const result = await ordersCollection.insertOne(orderInfo);
        // update product quantity
        const quantity = parseInt(orderInfo.quantity);
        await productsCollection.updateOne(
          {
            _id: new ObjectId(session.metadata.productId),
          },
          { $inc: { quantity: -quantity } }
        );

        return res.send({
          transactionId: session.payment_intent,
          orderId: result.insertedId,
          trackingId: result.trackingId,
        });
      }
      res.send(
        res.send({
          orderId: order._id,
          trackingId: order.trackingId,
          transactionId: session.payment_intent,
        })
      );
    });

    // get all orders for a customer by email
    app.get("/my-orders", verifyJWT, verifyBuyer, async (req, res) => {
      const result = await ordersCollection
        .find({ mail: req.tokenEmail })
        .toArray();
      res.send(result);
    });

    /////////////////////////////MANAGER ONLY/////////////////////////

    // get all products for a manager
    app.get("/manage-products", verifyJWT, verifyManager, async (req, res) => {
      const result = await productsCollection
        .find({ "manager.email": req.tokenEmail })
        .toArray();
      res.send(result);
    });

    // GET pending orders for a manager
    app.get("/pending-orders", verifyJWT, verifyManager, async (req, res) => {
      const pending = await ordersCollection
        .find({ "manager.email": req.tokenEmail, status: "pending" })
        .toArray();
      return res.send(pending);
    });

    // GET approved orders
    app.get("/approved-orders", verifyJWT, verifyManager, async (req, res) => {
      const approved = await ordersCollection
        .find({ "manager.email": req.tokenEmail, status: "approved" })
        .toArray();
      return res.send(approved);
    });

  
    //////////////////////////ADMIN ONLY////////////////////////////


    //////////////////////////////////////////////////////
    // get all users for admin
    app.get("/users", verifyJWT, verifyADMIN, async (req, res) => {
      const adminEmail = req.tokenEmail;
      const result = await usersCollection
        .find({ email: { $ne: adminEmail } })
        .toArray();
      res.send(result);
    });

    // update a user's role
    app.patch("/update-role", verifyJWT, verifyADMIN, async (req, res) => {
      const { email, role, status } = req.body;
      const result = await usersCollection.updateOne(
        { email },
        { $set: { role, status: "approved" } }
      );
      res.send(result);
    });

    // GET All orders for admin

    app.get("/all-products", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await productsCollection.find().toArray();
      res.send(result);
    });

    // GET All orders for admin
    app.get("/all-orders", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await ordersCollection.find().toArray();
      res.send(result);
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
