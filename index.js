require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const admin = require("firebase-admin");
const port = process.env.PORT || 5555;
const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf-8");
const crypto = require("crypto");
const serviceAccount = JSON.parse(decoded);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();

function generateTrackingId() {
  const prefix = "PRCL"; 
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, ""); 
  const random = crypto.randomBytes(3).toString("hex").toUpperCase(); 

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
  if (!token) return res.status(401).send({ message: "Unauthorized Access!" });
  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.tokenEmail = decoded.email;
    next();
  } catch (err) {
    console.log(err);
    return res.status(401).send({ message: "Unauthorized Access!", err });
  }
};

// Demo Profiles Mutation Blocker Middleware
const blockDemoMutations = (req, res, next) => {
  const demoEmails = ['user@demo.com', 'admin@demo.com', 'manager@demo.com'];
  const currentUserEmail = req.tokenEmail; 

  // Check 1: If current logged in user is a demo profile, block write operations
  if (currentUserEmail && demoEmails.includes(currentUserEmail.toLowerCase())) {
    return res.status(403).send({
      success: false,
      isDemoBlock: true,
      message: "Action denied: Write operations are disabled for demo profiles."
    });
  }
  
  // Check 2: If someone else tries to modify or suspend core demo accounts
  const targetEmail = req.body.email || req.query.email;
  if (targetEmail && demoEmails.includes(targetEmail.toLowerCase())) {
    return res.status(403).send({
      success: false,
      isDemoBlock: true,
      message: "Action denied: Core system demo profiles cannot be modified or suspended."
    });
  }
  next();
};

const client = new MongoClient(process.env.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    const db = client.db("garmentsDB");
    const productsCollection = db.collection("products");
    const ordersCollection = db.collection("orders");
    const usersCollection = db.collection("users");
    const trackingsCollection = db.collection("trackings");

    //////////////////////////////////////////////////////
    // Fixed Role Middlewares (Removed Comma Operator Bug)

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
      if (user?.role !== "buyer" && user?.status !== "approved") {
        return res
          .status(403)
          .send({ message: "Buyer only Action or Account not approved!", role: user?.role });
      }
      next();
    };

    const verifyManager = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      if (user?.role !== "manager" && user?.status !== "approved") {
        return res
          .status(403)
          .send({ message: "Manager only Action or Account not approved!", role: user?.role });
      }
      next();
    };

    const verifyAdminOrManager = async (req, res, next) => {
      const email = req.tokenEmail;
      const user = await usersCollection.findOne({ email });
      
      const isAuthorizedRole = user?.role === "manager" || user?.role === "admin";
      const isApproved = user?.status === "approved";

      if (!isAuthorizedRole || !isApproved) {
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

    async function insertTrackingLog(log) {
      const result = await trackingsCollection.insertOne(log);
      return result;
    }

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
      userData.status = "pending";
      userData.role = "User";

      const query = { email: userData.email };
      const alreadyExists = await usersCollection.findOne(query);

      if (alreadyExists) {
        const result = await usersCollection.updateOne(query, {
          $set: { last_loggedIn: new Date().toISOString() },
        });
        return res.send(result);
      }

      const result = await usersCollection.insertOne(userData);
      res.send(result);
    });

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
      res.send({ products, total, page: pageNum, limit: pageLimit });
    });

    app.get("/product/:id", verifyJWT, async (req, res) => {
      const id = req.params.id;
      const result = await productsCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // CASH ON DELIVERY ORDER
    app.post(
      "/cod-order",
      verifyJWT,
      verifyBuyer,
      blockSuspendedBuyer,
      blockDemoMutations, // Added Protection
      async (req, res) => {
        try {
          const paymentInfo = req.body;
          const product = await productsCollection.findOne({ _id: new ObjectId(paymentInfo.productId) });

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
      blockDemoMutations, // Added Protection
      async (req, res) => {
        const paymentInfo = req.body;
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
        res.send({ url: session.url });
      }
    );

    app.post("/payment-success", verifyJWT, verifyBuyer, blockDemoMutations, async (req, res) => {
      const { sessionId } = req.body;
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      const product = await productsCollection.findOne({ _id: new ObjectId(session.metadata.productId) });
      const order = await ordersCollection.findOne({ transactionId: session.payment_intent });

      if (session.status === "complete" && product && !order) {
        const paymentInfo = {
          productId: session.metadata.productId,
          transactionId: session.payment_intent,
          customer: session.metadata.customer,
          status: "pending",
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
        const result = await ordersCollection.insertOne(paymentInfo);
        const quantity = parseInt(paymentInfo.quantity);
        await productsCollection.updateOne(
          { _id: new ObjectId(session.metadata.productId) },
          { $inc: { quantity: -quantity } }
        );

        return res.send({
          transactionId: session.payment_intent,
          orderId: result.insertedId,
          trackingId: paymentInfo.trackingId,
        });
      }

      res.send({
        orderId: order?._id,
        trackingId: order?.trackingId,
        transactionId: session.payment_intent,
      });
    });

    app.get("/my-orders", verifyJWT, verifyBuyer, async (req, res) => {
      const result = await ordersCollection.find({ customer: req.tokenEmail }).toArray();
      res.send(result);
    });

    app.delete("/orders/:orderId", verifyJWT, blockDemoMutations, async (req, res) => {
      const orderId = req.params.orderId;
      const order = await ordersCollection.findOne({ _id: new ObjectId(orderId) });
      if (!order) return res.status(404).send({ message: "Order not found" });

      const deleteResult = await ordersCollection.deleteOne({ _id: new ObjectId(orderId) });

      if (deleteResult.deletedCount === 1 && order.productId && order.quantity) {
        await productsCollection.updateOne(
          { _id: new ObjectId(order.productId) },
          { $inc: { quantity: Number(order.quantity) } }
        );
      }
      return res.send({ success: true, deletedCount: deleteResult.deletedCount });
    });

    app.patch("/orders/cancel/:orderId", verifyJWT, blockDemoMutations, async (req, res) => {
      const orderId = req.params.orderId;
      const order = await ordersCollection.findOne({ _id: new ObjectId(orderId) });

      if (!order) return res.status(404).send({ message: "Order not found" });
      if (order.customer !== req.tokenEmail) {
        return res.status(403).send({ message: "Forbidden: you can only cancel your own orders" });
      }

      const update = {
        $set: {
          status: "cancelled",
          cancelledAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      };

      const result = await ordersCollection.updateOne({ _id: new ObjectId(orderId) }, update);

      if (order.productId && order.quantity) {
        await productsCollection.updateOne(
          { _id: new ObjectId(order.productId) },
          { $inc: { quantity: Number(order.quantity) } }
        );
      }
      res.send({ success: true, modifiedCount: result.modifiedCount });
    });

    // POST Products (Manager Only)
    app.post(
      "/products",
      verifyJWT,
      verifyManager,
      blockSuspendedManager,
      blockDemoMutations, // Added Protection
      async (req, res) => {
        const productData = req.body;
        const result = await productsCollection.insertOne(productData);
        res.send(result);
      }
    );

    app.get("/manage-products", verifyJWT, verifyManager, async (req, res) => {
      const result = await productsCollection.find({ "manager.email": req.tokenEmail }).toArray();
      res.send(result);
    });

    app.get("/pending-orders", verifyJWT, verifyManager, async (req, res) => {
      const pending = await ordersCollection.find({ "manager.email": req.tokenEmail, status: "pending" }).toArray();
      return res.send(pending);
    });

    app.get("/approved-orders", verifyJWT, async (req, res) => {
      const approved = await ordersCollection.find({ "manager.email": req.tokenEmail, status: "approved" }).toArray();
      return res.send(approved);
    });

    app.patch(
      "/order/:id/status",
      verifyJWT,
      verifyManager,
      blockSuspendedManager,
      blockDemoMutations,
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

    app.get("/orders/:orderId", verifyJWT, async (req, res) => {
      const id = req.params.orderId;
      const order = await ordersCollection.findOne({ _id: new ObjectId(id) });
      res.send(order);
    });

    app.post(
      "/orders/:orderId/tracking",
      verifyJWT,
      verifyManager,
      blockDemoMutations, // Added Protection
      async (req, res) => {
        const orderId = req.params.orderId;
        const order = await ordersCollection.findOne({ _id: new ObjectId(orderId) });
        if (!order) return res.status(404).send({ message: "Order not found" });

        const { status, location = "", note = "", timestamp } = req.body;
        const log = {
          orderId,
          trackingId: order.trackingId || null,
          status: String(status),
          location: String(location),
          note: String(note),
          timestamp: timestamp ? new Date(timestamp).toISOString() : new Date().toISOString(),
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

    // ADMIN ONLY ROUTES
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
      res.send({ users, total, page: pageNum, limit: pageLimit });
    });

    app.patch("/update-role", verifyJWT, verifyADMIN, blockDemoMutations, async (req, res) => {
      const { email, role, status } = req.body;
      const result = await usersCollection.updateOne(
        { email },
        { $set: { role, status: "approved" } }
      );
      res.send(result);
    });

    app.patch("/all-products", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await productsCollection.find().toArray();
      res.send(result);
    });

    app.get("/all-orders", verifyJWT, verifyADMIN, async (req, res) => {
      const result = await ordersCollection.find().toArray();
      res.send(result);
    });

    app.patch("/suspend-user", verifyJWT, verifyADMIN, blockDemoMutations, async (req, res) => {
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
          suspendedAt: suspended ? suspendedAt || new Date().toISOString() : null,
          reason: reason || null,
          feedback: feedback || null,
          suspendedBy: req.tokenEmail || null,
        },
        updatedAt: new Date().toISOString(),
      };
      const result = await usersCollection.updateOne({ email }, { $set: update });
      res.send({ success: true, modifiedCount: result.modifiedCount });
    });

    app.patch(
      "/update-product/:id",
      verifyJWT,
      verifyAdminOrManager,
      blockDemoMutations,
      async (req, res) => {
        const id = req.params.id;
        const payload = req.body; 
        if (payload.price !== undefined) payload.price = Number(payload.price);
        if (payload.quantity !== undefined) payload.quantity = Number(payload.quantity);
        if (payload.moq !== undefined) payload.moq = Number(payload.moq);
        if (payload.showOnHome !== undefined) payload.showOnHome = Boolean(payload.showOnHome);

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
      blockDemoMutations,
      async (req, res) => {
        const id = req.params.id;
        const query = { _id: new ObjectId(id) };
        const result = await productsCollection.deleteOne(query);
        res.send(result);
      }
    );

    app.get("/orders/:orderId/tracking", verifyJWT, async (req, res) => {
      const orderId = req.params.orderId;
      const logs = await trackingsCollection
        .find({ orderId })
        .sort({ timestamp: 1, createdAt: 1 })
        .toArray();
      if (!logs.length) {
        const order = await ordersCollection.findOne({ _id: new ObjectId(orderId) });
        return res.send({ logs: order?.tracking || [] });
      }
      res.send({ logs });
    });

    app.patch("/orders/:orderId/tracking", verifyJWT, blockDemoMutations, async (req, res) => {
      const orderId = req.params.orderId;
      const order = await ordersCollection.findOne({ _id: new ObjectId(orderId) });
      if (!order) return res.status(404).send({ message: "Order not found" });
      const { status, location = "", note = "", timestamp } = req.body;

      const log = {
        orderId,
        trackingId: order.trackingId || null,
        status: String(status),
        location: String(location),
        note: String(note),
        timestamp: timestamp ? new Date(timestamp).toISOString() : new Date().toISOString(),
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

    app.patch("/orders/close/:orderId", verifyJWT, blockDemoMutations, async (req, res) => {
      const orderId = req.params.orderId;
      const update = {
        $set: {
          status: "delivered",
          deliveredAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      };
      const result = await ordersCollection.updateOne({ _id: new ObjectId(orderId) }, update);
      res.send({ success: true, modifiedCount: result.modifiedCount });
    });

    app.get("/user", verifyJWT, async (req, res) => {
      const user = await usersCollection.findOne(
        { email: req.tokenEmail },
        { projection: { password: 0 } }
      );
      res.send({ user });
    });

    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("TailorFlow Server is talking..");
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`TailorFlow Server is running on port ${port}`);
  });
}

module.exports = app;