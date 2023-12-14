const express = require("express");
const router = express.Router();

const { isAuthenticatedUser, authorizeRoles } = require("../middleware/authMiddle");
const {
  Checkgroup,
  checkLogin,
  loginUser,
  logout,
  registerUser,
  getUsers,
  getUser,
  toggleUserStatus,
  updateUser,
  updateUserEmail,
  updateUserPassword,
  createGroup,
  getGroups,
  createApp,
  createPlan,
  createTask,
  getApps,
  updateApp,
  getPlans,
} = require("../controllers/controllers");

router.route("/login").post(loginUser);
router.route("/_logout").get(isAuthenticatedUser, logout);
router.route("/register").post(isAuthenticatedUser, authorizeRoles("admin"), registerUser);
router.route("/createGroup").post(isAuthenticatedUser, authorizeRoles("admin"), createGroup);

router.route("/getUsers").get(isAuthenticatedUser, getUsers);
router.route("/getUser").get(isAuthenticatedUser, getUser);
router.route("/toggleUserStatus/:username").put(isAuthenticatedUser, authorizeRoles("admin"), toggleUserStatus);
router.route("/updateUser/:username").put(isAuthenticatedUser, authorizeRoles("admin"), updateUser);
router.route("/updateUserEmail/").put(isAuthenticatedUser, updateUserEmail);
router.route("/updateUserPassword/").put(isAuthenticatedUser, updateUserPassword);
router.route("/getGroups").get(isAuthenticatedUser, getGroups);

router.route("/getApps").get(isAuthenticatedUser, getApps);
router.route("/createApp").post(isAuthenticatedUser, authorizeRoles("PL"), createApp);
router.route("/updateApp/:appname").put(isAuthenticatedUser, authorizeRoles("PL"), updateApp);
router.route("/getPlans").post(isAuthenticatedUser, authorizeRoles("PM"), getPlans);
router.route("/createPlan").post(isAuthenticatedUser, authorizeRoles("PM"), createPlan);
router.route("/createTask").post(isAuthenticatedUser, authorizeRoles("PL"), createTask);

router.route("/checkGroup").post(isAuthenticatedUser, async (req, res, next) => {
  const username = req.user.username;
  const group = req.body.group;
  const result = await Checkgroup(username, group);
  res.json(result);
});

router.route("/checkLogin").get(isAuthenticatedUser, async (req, res, next) => {
  const token = req.token;
  const result = await checkLogin(token);
  res.json(result);
});

module.exports = router;
