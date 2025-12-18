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
  // console.log(token);
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
    const trackingsCollection = db.collection("trackings");
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
    const verifyAdminOrManager = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (
        (user?.role !== "manager" || user?.role !== "admin",
        user?.status !== "approved")
      ) {
        return res
          .status(403)
          .send({ message: "Manager or Admin Action only!", role: user?.role });
      }
      next();
    };

    async function blockSuspendedBuyer(req, res, next) {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user.role === "buyer" && user.suspended?.status) {
        return res.status(403).send({
          message: "Account suspended. New orders/bookings are not allowed.",
          feedback: user.suspended?.feedback || null,
        });
      }
      next();
    }

    async function blockSuspendedManager(req, res, next) {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user.role === "manager" && user.suspended?.status) {
        return res.status(403).send({
          message: "Account suspended. Allowed Manager Actions only.",
          feedback: user.suspended?.feedback || null,
        });
      }
      next();
    }

    //////////////////////////////////////////////////////

    async function insertTrackingLog(log) {
      const result = await trackingsCollection.insertOne(log);
      return result;
    }

    ////////////////////////////////////////////////////////////////

    // get a user's role
    app.get("/user/role", verifyJWT, async (req, res) => {
      const result = await usersCollection.findOne({ email: req.tokenEmail });
      res.send({ role: result?.role, status: result?.status });
    });
    // save or update a user in db
    app.post("/user", async (req, res) => {
      const userData = req.body;
      userData.created_at = new Date().toISOString();
      userData.last_loggedIn = new Date().toISOString();
      (userData.status = "pending"), (userData.role = "User");
      // console.log("From Data: ----> ", userData);

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
      // console.log("\n \n user data: --------> ", userData);
      res.send(result);
    });

    // GET all Products

    // GET /products
    app.get("/products", async (req, res) => {
      const {
        search,
        page = "1",
        limit = "6",
        sortBy = "createdAt",
        sortDir = "desc",
      } = req.query;

      const pageNum = Math.max(1, parseInt(page, 10) || 1);
      const pageLimit = Math.max(1, Math.min(100, parseInt(limit, 10) || 6));
      const skip = (pageNum - 1) * pageLimit;
      const sortDirection = sortDir === "asc" ? 1 : -1;

      const query = {};
      if (search && String(search).trim()) {
        const q = String(search).trim();
        query.$or = [
          { title: { $regex: q, $options: "i" } },
          { description: { $regex: q, $options: "i" } },
        ];
      }

      const total = await productsCollection.countDocuments(query);

      const cursor = productsCollection
        .find(query)
        .sort({ [sortBy]: sortDirection })
        .skip(skip)
        .limit(pageLimit);

      const products = await cursor.toArray();

      res.send({
        products,
        total,
        page: pageNum,
        limit: pageLimit,
      });
    });

    ///////////////////////////CUSTOMER ONLY///////////////////////////

    // GET Single Product

    app.get("/product/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const result = await productsCollection.findOne({
        _id: new ObjectId(id),
      });
      res.send(result);
    });

    // Payment endpoints

    ///// CASH ON DELIVERY ORDER
    app.post(
      "/cod-order",
      verifyJWT,
      verifyBuyer,
      blockSuspendedBuyer,
      async (req, res) => {
        try {
          const paymentInfo = req.body;
          // console.log("\nCash on Deliver   :::   ===>\n",paymentInfo);return

          const product = await productsCollection.findOne({
            _id: new ObjectId(paymentInfo.productId),
          });

          if (!product) {
            return res.status(404).send({ message: "Product not found" });
          }
          const result = await ordersCollection.insertOne({
            ...paymentInfo,
            status: "pending",
            customer: paymentInfo.customer.email,
            quantity: parseInt(paymentInfo.orderQuantity),
            price: parseInt(paymentInfo.totalPrice),
            image: paymentInfo.images[0],
            trackingId: generateTrackingId(),
            createdAt: new Date().toISOString(),
          });
          await productsCollection.updateOne(
            { _id: new ObjectId(paymentInfo.productId) },
            { $inc: { quantity: -paymentInfo.orderQuantity } }
          );

          res.send({
            success: true,
            orderId: result.insertedId,
            trackingId: paymentInfo.trackingId,
          });
        } catch (err) {
          console.log(err);
          res.status(500).send({ message: "COD order failed" });
        }
      }
    );

    // create-checkout-session
    app.post(
      "/create-checkout-session",
      verifyJWT,
      verifyBuyer,
      blockSuspendedBuyer,
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
        const paymentInfo = {
          productId: session.metadata.productId,
          transactionId: session.payment_intent,
          customer: session.metadata.customer,
          status: "pending", // session.metadata.status = value is *complete*
          manager: product?.manager,
          name: product?.title,
          category: product?.category,
          quantity: parseInt(session.metadata.orderQuantity),
          price: session.amount_total / 100,
          currency: session.currency,
          paymentStatus: session.payment_status,
          createdAt: new Date(),
          image: product?.images[0],
          trackingId: generateTrackingId(),
          country: session.customer_details.country,
        };
        // console.log(paymentInfo);return
        const result = await ordersCollection.insertOne(paymentInfo);
        // update product quantity
        const quantity = parseInt(paymentInfo.quantity);
        await productsCollection.updateOne(
          {
            _id: new ObjectId(session.metadata.productId),
          },
          { $inc: { quantity: -quantity } }
        );
        logTracking(trackingId, "product_created");

        return res.send({
          transactionId: session.payment_intent,
          orderId: result.insertedId,
          trackingId: result.trackingId,
        });
      }

      res.send({
        orderId: order._id,
        trackingId: order.trackingId,
        transactionId: session.payment_intent,
      });
    });

    // get all orders for a customer by email
    app.get("/my-orders", verifyJWT, verifyBuyer, async (req, res) => {
      const result = await ordersCollection
        .find({ customer: req.tokenEmail })
        .toArray();
      res.send(result);
    });
    // Cancel an order (buyer only, simple)
    app.delete("/orders/:orderId", verifyJWT, async (req, res) => {
      const orderId = req.params.orderId;
      const deleteResult = await ordersCollection.deleteOne({
        _id: new ObjectId(orderId),
      });

      if (
        deleteResult.deletedCount === 1 &&
        order.productId &&
        order.quantity
      ) {
        await productsCollection.updateOne(
          { _id: new ObjectId(order.productId) },
          { $inc: { quantity: Number(order.quantity) } }
        );
      }

      return res.send({
        success: true,
        deletedCount: deleteResult.deletedCount,
      });
    });
    // Cancel an order (buyer only, simple)
    app.patch("/orders/cancel/:orderId", verifyJWT, async (req, res) => {
      const orderId = req.params.orderId;

      const order = await ordersCollection.findOne({
        _id: new ObjectId(orderId),
      });

      if (order.customer !== req.tokenEmail) {
        return res
          .status(403)
          .send({ message: "Forbidden: you can only cancel your own orders" });
      }
      const update = {
        $set: {
          status: "cancelled",
          cancelledAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      };

      const result = await ordersCollection.updateOne(
        { _id: new ObjectId(orderId) },
        update
      );

      if (order.productId && order.quantity) {
        await productsCollection.updateOne(
          { _id: new ObjectId(order.productId) },
          { $inc: { quantity: Number(order.quantity) } }
        );
      }
      res.send({ success: true, modifiedCount: result.modifiedCount });
    });

    /////////////////////////////MANAGER ONLY/////////////////////////

    // POST All Products

    app.post(
      "/products",
      verifyJWT,
      verifyManager,
      blockSuspendedManager,
      async (req, res) => {
        const productData = req.body;
        console.log(productData);
        const result = await productsCollection.insertOne(productData);
        res.send(result);
      }
    );

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
    app.get("/approved-orders", verifyJWT, async (req, res) => {
      const approved = await ordersCollection
        .find({ "manager.email": req.tokenEmail, status: "approved" })
        .toArray();
      return res.send(approved);
    });

    // PATCH status for a order
    app.patch(
      "/order/:id/status",
      verifyJWT,
      verifyManager,
      blockSuspendedManager,
      async (req, res) => {
        const id = req.params.id;
        const { status } = req.body;
        const updateFields = { status, updatedAt: new Date().toISOString() };

        if (status === "approved") {
          updateFields.approvedAt = new Date().toISOString();
          updateFields.rejectedAt = null;
        } else if (status === "rejected") {
          updateFields.rejectedAt = new Date().toISOString();
          updateFields.approvedAt = null;
        }

        const result = await ordersCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: updateFields }
        );
        res.send(result);
      }
    );

    // GET order details
    app.get("/orders/:orderId", verifyJWT, async (req, res) => {
      const id = req.params.orderId;
      const order = await ordersCollection.findOne({ _id: new ObjectId(id) });
      res.send(order);
    });
    // Add Tracking for a order
    app.post(
      "/orders/:orderId/tracking",
      verifyJWT,
      verifyManager,
      async (req, res) => {
        const orderId = req.params.orderId;

        const order = await ordersCollection.findOne({
          _id: new ObjectId(orderId),
        });
        const { status, location = "", note = "", timestamp } = req.body;
        const log = {
          orderId,
          trackingId: order.trackingId || null,
          status: String(status),
          location: String(location),
          note: String(note),
          timestamp: timestamp
            ? new Date(timestamp).toISOString()
            : new Date().toISOString(),
          createdAt: new Date().toISOString(),
          addedBy: req.decoded_email || null,
        };
        const insertResult = await insertTrackingLog(log);
        await ordersCollection.updateOne(
          { _id: new ObjectId(orderId) },
          {
            $push: { tracking: log },
            $set: { updatedAt: new Date().toISOString() },
          }
        );

        res.send({ success: true, insertedId: insertResult.insertedId, log });
      }
    );

    //////////////////////////ADMIN ONLY////////////////////////////

    //////////////////////////////////////////////////////
    // get all users for admin
    app.get("/users", verifyJWT, verifyADMIN, async (req, res) => {
      const othersQuery = { email: { $ne: "admin@gamil.com" } };
      const query = { ...othersQuery };
      const {
        searchText,
        role,
        status,
        page = "1",
        limit = "20",
        sortBy = "createdAt",
        sortDir = "desc",
      } = req.query;

      const pageNum = Math.max(1, parseInt(page, 10) || 1);
      const pageLimit = Math.max(1, Math.min(100, parseInt(limit, 10) || 20));
      const skip = (pageNum - 1) * pageLimit;

      if (searchText && String(searchText).trim()) {
        const q = String(searchText).trim();
        query.$or = [
          { name: { $regex: q, $options: "i" } },
          { email: { $regex: q, $options: "i" } },
        ];
      }
      if (role && String(role).trim()) {
        query.role = String(role).trim();
      }
      if (status === "suspended") {
        query["suspended.status"] = true;
      } else if (status === "active") {
        query.$or = query.$or || [];
        query.$or.push(
          { "suspended.status": { $exists: false } },
          { "suspended.status": false }
        );
      }
      const sortDirection = sortDir === "asc" ? 1 : -1;
      const sort = { [sortBy]: sortDirection };

      const total = await usersCollection.countDocuments(query);
      const cursor = usersCollection
        .find(query)
        .sort(sort)
        .skip(skip)
        .limit(pageLimit);

      const users = await cursor.toArray();

      res.send({
        users,
        total,
        email: { $ne: "admin@gamil.com" },
        page: pageNum,
        limit: pageLimit,
      });
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

    app.patch("/all-products", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await productsCollection.find().toArray();
      res.send(result);
    });

    // GET All orders for admin
    app.get("/all-orders", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await ordersCollection.find().toArray();
      res.send(result);
    });

    //suspend-user
    app.patch("/suspend-user", verifyJWT, verifyADMIN, async (req, res) => {
      const {
        email,
        suspended,
        suspendedAt = null,
        reason = null,
        feedback = null,
      } = req.body;
      const update = {
        suspended: {
          status: Boolean(suspended),
          suspendedAt: suspended
            ? suspendedAt || new Date().toISOString()
            : null,
          reason: reason || null,
          feedback: feedback || null,
          suspendedBy: req.tokenEmail || null,
        },
        updatedAt: new Date().toISOString(),
      };
      const result = await usersCollection.updateOne(
        { email },
        { $set: update }
      );
      res.send({ success: true, modifiedCount: result.modifiedCount });
    });

    /////////////////////////////////////////////////////////////////////////
    app.patch(
      "/update-product/:id",
      verifyJWT,
      verifyAdminOrManager,
      async (req, res) => {
        const id = req.params.id;
        const payload = req.body; // send only the fields you want to change
        if (payload.price !== undefined) payload.price = Number(payload.price);
        if (payload.quantity !== undefined)
          payload.quantity = Number(payload.quantity);
        if (payload.moq !== undefined) payload.moq = Number(payload.moq);
        if (payload.showOnHome !== undefined)
          payload.showOnHome = Boolean(payload.showOnHome);

        const result = await productsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { ...payload, updatedAt: new Date().toISOString() } }
        );

        res.send(result);
      }
    );

    app.delete(
      "/delete-product/:id",
      verifyJWT,
      verifyAdminOrManager,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };

        const result = await productsCollection.deleteOne(query);
        res.send(result);
      }
    );
    ///////////////////////////////////////////////////
    // tracking logs for an order
    app.get("/orders/:orderId/tracking", verifyJWT, async (req, res) => {
      const orderId = req.params.orderId;
      const logs = await trackingsCollection
        .find({ orderId })
        .sort({ timestamp: 1, createdAt: 1 })
        .toArray();
      if (!logs.length) {
        const order = await ordersCollection.findOne({
          _id: new ObjectId(orderId),
        });
        return res.send({ logs: order?.tracking || [] });
      }
      res.send({ logs });
    });

    // single tracking entry "Mark Delivered"
    app.patch("/orders/:orderId/tracking", verifyJWT, async (req, res) => {
      const orderId = req.params.orderId;

      const order = await ordersCollection.findOne({
        _id: new ObjectId(orderId),
      });
      if (!order) return res.status(404).send({ message: "Order not found" });
      const { status, location = "", note = "", timestamp } = req.body;

      const log = {
        orderId,
        trackingId: order.trackingId || null,
        status: String(status),
        location: String(location),
        note: String(note),
        timestamp: timestamp
          ? new Date(timestamp).toISOString()
          : new Date().toISOString(),
        createdAt: new Date().toISOString(),
        addedBy: req.decoded_email || null,
      };

      const insertResult = await insertTrackingLog(log);

      await ordersCollection.updateOne(
        { _id: new ObjectId(orderId) },
        {
          $push: { tracking: log },
          $set: { updatedAt: new Date().toISOString() },
        }
      );

      res.send({ success: true, insertedId: insertResult.insertedId, log });
    });
    // sets final status and deliveredAt
    app.patch("/orders/close/:orderId", verifyJWT, async (req, res) => {
      const orderId = req.params.orderId;
      const update = {
        $set: {
          status: "delivered",
          deliveredAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      };
      const result = await ordersCollection.updateOne(
        { _id: new ObjectId(orderId) },
        update
      );
      res.send({ success: true, modifiedCount: result.modifiedCount });
    });
    // User Profile endpoint
    app.get("/user", verifyJWT, async (req, res) => {
      const user = await usersCollection.findOne(
        { email: req.tokenEmail },
        { projection: { password: 0 } }
      );
      res.send({ user });
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
