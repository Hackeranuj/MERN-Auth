const express = require("express");
const authMiddleware = require("../middleware/auth-middleware");
const adminMiddleware = require("../middleware/admin-middleware");
const uploadMiddleware = require("../middleware/upload-middleware");
const {
  uploadImageController,
  fetchImagesController,
  deleteImageController,
} = require("../controllers/image-controller");
// 67877324a6a6321f1c5b97a6
const router = express.Router();

// upload the image
router.post(
  "/upload",
  authMiddleware,
  adminMiddleware,
  uploadMiddleware.single("image"),
  uploadImageController
);

// get all the images
router.get("/get", authMiddleware, fetchImagesController);

// delete image
router.delete("/:id", authMiddleware, adminMiddleware, deleteImageController);

module.exports = router;
