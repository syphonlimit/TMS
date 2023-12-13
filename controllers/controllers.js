const catchAsyncErrors = require("../middleware/catchAsyncErrors");
const ErrorResponse = require("../utils/errorHandler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

//Setting up database connection
const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});
if (connection) console.log(`MySQL Database connected with host: ${process.env.DB_HOST}`);

// checkGroup(username, group) to check if a user is in a group
exports.Checkgroup = async function (userid, groupname) {
  //get user from database
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [userid]);
  if (row.length === 0) {
    return false;
  }
  const user = row[0];
  //User can have multiple groups delimited by ,{group},{group}. We need to split them into an array
  user.group_list = user.group_list.split(",");
  //if any of the user's groups is included in the roles array, then the user is authorized. The group has to match exactly
  //for each group in the group array, check match exact as group parameter
  authorised = user.group_list.includes(groupname);
  if (!authorised) {
    return false;
  }
  return true;
};

exports.checkLogin = catchAsyncErrors(async function (token) {
  if (token === "null" || !token) {
    return false;
  }
  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return false;
  }

  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [decoded.username]);
  const user = row[0];
  if (user === undefined) {
    return false;
  }

  if (user.is_disabled === 1) {
    return false;
  }
  return true;
});

// Login a user => /login
exports.loginUser = catchAsyncErrors(async (req, res, next) => {
  //get username and password from request body
  const { username, password } = req.body;

  //check if username and password is provided
  if (!username || !password) {
    return next(new ErrorResponse("Invalid username or password", 400));
  }

  //find user in database
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username]);
  if (row.length === 0) {
    return next(new ErrorResponse("Invalid username or password", 401));
  }
  //get user from row
  const user = row[0];

  //Use bcrypt to compare password
  const isPasswordMatched = await bcrypt.compare(password, user.password);
  if (!isPasswordMatched) {
    return next(new ErrorResponse("Invalid username or password", 401));
  }

  //Check if user is disabled
  if (user.is_disabled === 1) {
    return next(new ErrorResponse("Invalid username or password", 401));
  }

  //Send token
  sendToken(user, 200, res);
});

// Logout a user => /_logout
exports.logout = catchAsyncErrors(async (req, res, next) => {
  //Send response
  res.status(200).json({
    success: true,
    message: "Logged out",
  });
});

// Create a user => /register
exports.registerUser = catchAsyncErrors(async (req, res, next) => {
  const { username, password, email, group_list } = req.body;

  if (req.body.username === "" || null) {
    return next(new ErrorResponse("Please enter input in the username", 400));
  }

  //We need to check for password constraint, minimum character is 8 and maximum character is 10. It should include alphanumeric, number and special character. We do not care baout uppercase and lowercase.
  const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/;
  if (!passwordRegex.test(password)) {
    return next(new ErrorResponse("Password must be 8-10 characters long, contain at least one number, one letter and one special character", 400));
  }

  //Bcrypt password with salt 10
  const hashedPassword = await bcrypt.hash(password, 10);
  let result;
  try {
    result = await connection
      .promise()
      .execute("INSERT INTO user (username, password, email, `group_list`, is_disabled) VALUES (?,?,?,?,?)", [
        username,
        hashedPassword,
        email,
        group_list,
        0,
      ]);
  } catch (err) {
    //check duplicate entry
    if (err.code === "ER_DUP_ENTRY") {
      return next(new ErrorResponse("Username already exists", 400));
    }
  }
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create user", 500));
  }

  res.status(200).json({
    success: true,
    message: "User created successfully",
  });
});

// Create a group => /controller/createGroup
exports.createGroup = catchAsyncErrors(async (req, res, next) => {
  const { group_name } = req.body;

  //split group_name by comma
  const group_name_list = group_name.split(",");

  //Check if group already exists
  const [row, fields] = await connection.promise().query("SELECT * FROM usergroups WHERE group_name IN (?)", [group_name_list]);
  if (row.length !== 0) {
    return next(new ErrorResponse("Group already exists", 400));
  }

  //Regex to check if group name is alphanumeric and no space
  const groupRegex = /^[a-zA-Z0-9]+$/;
  for (let i = 0; i < group_name_list.length; i++) {
    if (!groupRegex.test(group_name_list[i])) {
      return next(new ErrorResponse("Group name must be alphanumeric and no space", 400));
    }
  }

  //Insert group into database one by one
  for (let i = 0; i < group_name_list.length; i++) {
    const result = await connection.promise().execute("INSERT INTO usergroups (group_name) VALUES (?)", [group_name_list[i]]);

    if (result[0].affectedRows === 0) {
      return next(new ErrorResponse("Failed to create group", 500));
    }
  }

  res.status(200).json({
    success: true,
    message: "Group(s) created successfully",
  });
});

// Get all users => /controller/getUsers
exports.getUsers = catchAsyncErrors(async (req, res, next) => {
  const [rows, fields] = await connection.promise().query("SELECT username,email,group_list,is_disabled FROM user where not username='admin'");
  res.status(200).json({
    success: true,
    data: rows,
  });
});

// Get a user => /controller/getUser
exports.getUser = catchAsyncErrors(async (req, res, next) => {
  const username = req.user.username;
  const [row, fields] = await connection.promise().query("SELECT username,email,group_list FROM user WHERE username = ?", [username]);
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404));
  }
  res.status(200).json({
    success: true,
    data: row[0],
  });
});

// Toggle user status => /controller/toggleUserStatus/:username
exports.toggleUserStatus = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.params.username]);
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404));
  }

  const user = row[0];
  //new status should be flip of current status
  const newStatus = user.is_disabled === 1 ? 0 : 1;
  const result = await connection.promise().execute("UPDATE user SET is_disabled = ? WHERE username = ?", [newStatus, req.params.username]);
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500));
  }

  res.status(200).json({
    success: true,
    message: "User updated successfully",
  });
});

// Update a user (admin) => /controller/updateUser/:username
exports.updateUser = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [req.params.username]);
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404));
  }
  const user = row[0];
  //We need to check for password constraint, minimum character is 8 and maximum character is 10. It should include alphanumeric, number and special character. We do not care baout uppercase and lowercase.
  const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/;
  if (req.body.password && !passwordRegex.test(req.body.password)) {
    return next(new ErrorResponse("Password must be 8-10 characters long, contain at least one number, one letter and one special character", 400));
  }

  //the fields are optional to update, so we need to build the query dynamically
  let query = "UPDATE user SET ";
  let values = [];
  //Updatable fields are email, password, groups.
  if (req.body.email) {
    query += "email = ?, ";
    values.push(req.body.email);
  } else if (req.body.email === undefined) {
    query += "email = ?, ";
    values.push(null);
  }
  if (req.body.password) {
    query += "password = ?, ";
    //bcrypt password with salt 10
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    values.push(hashedPassword);
  }
  if (req.body.group) {
    query += "`group_list` = ?, ";
    values.push(req.body.group);
  }
  //group can be empty, if it is empty we should update the group_list to empty
  if (req.body.group === "") {
    query += "`group_list` = ?, ";
    values.push("");
  }
  //remove the last comma and space
  query = query.slice(0, -2);
  //add the where clause
  query += " WHERE username = ?";
  values.push(req.params.username);
  const result = await connection.promise().execute(query, values);
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500));
  }

  res.status(200).json({
    success: true,
    message: "User updated successfully",
  });
});

// Update user email (user) => /controller/updateUserEmail/:username
exports.updateUserEmail = catchAsyncErrors(async (req, res, next) => {
  const username = req.user.username;
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username]);
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404));
  }

  const user = row[0];
  const result = await connection.promise().execute("UPDATE user SET email = ? WHERE username = ?", [req.body.email, username]);
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500));
  }

  res.status(200).json({
    success: true,
    message: "User updated successfully",
  });
});

// Update user password (user) => /controller/updateUserPassword/:username
exports.updateUserPassword = catchAsyncErrors(async (req, res, next) => {
  const username = req.user.username;
  const [row, fields] = await connection.promise().query("SELECT * FROM user WHERE username = ?", [username]);
  if (row.length === 0) {
    return next(new ErrorResponse("User not found", 404));
  }

  const user = row[0];
  //password constraint check
  const passwordRegex = /^(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,10}$/;
  if (!passwordRegex.test(req.body.password)) {
    return next(new ErrorResponse("Password must be 8-10 characters long, contain at least one number, one letter and one special character", 400));
  }

  //bcrypt new password with salt 10
  const hashedPassword = await bcrypt.hash(req.body.password, 10);

  const result = await connection.promise().execute("UPDATE user SET password = ? WHERE username = ?", [hashedPassword, username]);
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update user", 500));
  }

  sendToken(user, 200, res);
});

// Get all groups in usergroups table => /controller/getGroups
exports.getGroups = catchAsyncErrors(async (req, res, next) => {
  const [rows, fields] = await connection.promise().query("SELECT * FROM usergroups");
  if (rows.length === 0) {
    return next(new ErrorResponse("No groups found", 404));
  }
  res.status(200).json({
    success: true,
    data: rows,
  });
});

//Create Application => /controller/createApp
exports.createApp = catchAsyncErrors(async (req, res, next) => {
  const { application, description, rNum, startDate, endDate, permOpen, permToDo, permDoing, permDone, permCreate } = req.body;

  if (req.body.application === "" || null) {
    return next(new ErrorResponse("Please enter input for the App name", 400));
  }

  if (req.body.rNum === "" || null) {
    return next(new ErrorResponse("Please enter input for the App rNumber", 400));
  }

  //rNum constraint check
  const rNumRegex = /^[0-9]+$/;
  if (!rNumRegex.test(req.body.rNum)) {
    return next(new ErrorResponse("Rnumber can only be a postive integer", 400));
  }

  if (req.body.description === "" || null) {
    return next(new ErrorResponse("Please enter description for the App", 400));
  }

  let result;
  try {
    result = await connection
      .promise()
      .execute(
        "INSERT INTO application (App_Acronym, App_startDate, App_endDate, App_Rnumber, App_Description, App_permit_create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done) VALUES (?,?,?,?,?,?,?,?,?,?)",
        [application, startDate, endDate, rNum, description, permCreate, permOpen, permToDo, permDoing, permDone]
      );
  } catch (error) {
    //check duplicate entry
    if (error.code === "ER_DUP_ENTRY") {
      return next(new ErrorResponse("Appname already exists", 400));
    }
  }
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create app", 500));
  }

  res.status(200).json({
    success: true,
    message: "App created successfully",
  });
});

// Get all apps => /controller/getApps
exports.getApps = catchAsyncErrors(async (req, res, next) => {
  const [rows, fields] = await connection
    .promise()
    .query(
      "SELECT App_Acronym, App_startDate, App_endDate, App_Rnumber, App_Description, App_permit_create, App_permit_Open, App_permit_toDoList, App_permit_Doing, App_permit_Done FROM application"
    );
  res.status(200).json({
    success: true,
    data: rows,
  });
});

//Update App details => /controller/updateApp/:appname
exports.updateApp = catchAsyncErrors(async (req, res, next) => {
  const [row, fields] = await connection.promise().query("SELECT * FROM application WHERE App_Acronym = ?", [req.params.appname]);
  if (row.length === 0) {
    return next(new ErrorResponse("App not found", 404));
  }
  const app = row[0];

  //the fields are optional to update, so we need to build the query dynamically
  let query = "UPDATE application SET ";
  let values = [];
  //Updatable fields are start/end dates, description, App permissions.
  if (req.body.startDate) {
    query += "App_startDate = ?, ";
    values.push(req.body.startDate);
  } else if (req.body.startDate === undefined) {
    query += "App_startDate = ?, ";
    values.push(null);
  }
  if (req.body.endDate) {
    query += "App_endDate = ?, ";
    values.push(req.body.endDate);
  } else if (req.body.endDate === undefined) {
    query += "App_endDate = ?, ";
    values.push(null);
  }
  if (req.body.description) {
    query += "App_Description = ?, ";
    values.push(req.body.description);
  } else if (req.body.description === undefined) {
    query += "App_Description = ?, ";
    values.push("");
  }
  if (req.body.permCreate) {
    query += "App_permit_create = ?, ";
    values.push(req.body.permCreate);
  }
  if (req.body.permOpen) {
    query += "App_permit_Open = ?, ";
    values.push(req.body.permOpen);
  }
  if (req.body.permToDo) {
    query += "App_permit_toDoList = ?, ";
    values.push(req.body.permToDo);
  }
  if (req.body.permDoing) {
    query += "App_permit_Doing = ?, ";
    values.push(req.body.permDoing);
  }
  if (req.body.permDone) {
    query += "App_permit_Done = ?, ";
    values.push(req.body.permDone);
  }
  //group can be empty, if it is empty we should update the permission to empty
  if (req.body.permCreate === "") {
    query += "App_permit_create = ?, ";
    values.push("");
  }
  if (req.body.permOpen === "") {
    query += "App_permit_Open = ?, ";
    values.push("");
  }
  if (req.body.permToDo === "") {
    query += "App_permit_toDoList = ?, ";
    values.push("");
  }
  if (req.body.permDoing === "") {
    query += "App_permit_Doing = ?, ";
    values.push("");
  }
  if (req.body.permDone === "") {
    query += "App_permit_Done = ?, ";
    values.push("");
  }
  //remove the last comma and space
  query = query.slice(0, -2);
  //add the where clause
  query += " WHERE App_Acronym = ?";
  values.push(req.params.appname);
  const result = await connection.promise().execute(query, values);
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to update app", 500));
  }

  res.status(200).json({
    success: true,
    message: "App updated successfully",
  });
});

//Create Plan => /controller/createPlan
exports.createPlan = catchAsyncErrors(async (req, res, next) => {
  const { Plan_MVP_name, Plan_startDate, Plan_endDate, Plan_app_Acronym } = req.body;

  if (req.body.Plan_MVP_name === "" || null) {
    return next(new ErrorResponse("Please enter input for the Plan name", 400));
  }

  let result;
  try {
    result = await connection
      .promise()
      .execute("INSERT INTO plan (Plan_MVP_name, Plan_startDate, Plan_endDate, Plan_app_Acronym) VALUES (?,?,?,?)", [
        Plan_MVP_name,
        Plan_startDate,
        Plan_endDate,
        Plan_app_Acronym,
      ]);
  } catch (error) {
    //check duplicate entry
    if (error.code === "ER_DUP_ENTRY") {
      return next(new ErrorResponse("Plan name already exists", 400));
    }
  }
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create plan", 500));
  }

  res.status(200).json({
    success: true,
    message: "Plan created successfully",
  });
});

//Create Task => /controller/createTask
exports.createTask = catchAsyncErrors(async (req, res, next) => {
  const { name, description, acronym } = req.body;
  const token = req.token;
  if (req.body.name === "" || null) {
    return next(new ErrorResponse("Please enter input for the Task name", 400));
  }

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return false;
  }

  let notes = decoded.username + " Open " + Date.now();
  let rnum = await connection.promise().execute("SELECT App_Rnumber FROM application where App_Acronym = ?", [acronym]);
  let rnumber = rnum[0][0].App_Rnumber + 1;
  let Task_id = acronym + rnumber;
  let result;
  try {
    result = await connection
      .promise()
      .execute(
        "INSERT INTO task (Task_name, Task_description, Task_notes, Task_id, Task_app_Acronym, Task_state, Task_creator, Task_owner) VALUES (?,?,?,?,?,?,?,?)",
        [name, description, notes, Task_id, acronym, "open", decoded.username, decoded.username]
      );
    updateRnum = await connection.promise().execute("UPDATE application SET App_Rnumber = ? where App_Acronym = ?", [rnumber, acronym]);
  } catch (error) {
    //check duplicate entry
    if (error.code === "ER_DUP_ENTRY") {
      return next(new ErrorResponse("Task name already exists", 400));
    } else {
      return next(new ErrorResponse("Task failed", 400));
    }
  }
  if (result[0].affectedRows === 0) {
    return next(new ErrorResponse("Failed to create Task", 500));
  }

  res.status(200).json({
    success: true,
    message: "Task created successfully",
  });
});

// Create and send token and save in cookie
const sendToken = (user, statusCode, res) => {
  // Create JWT Token
  const token = getJwtToken(user);
  // Options for cookie
  const options = {
    expires: new Date(Date.now() + process.env.COOKIE_EXPIRES_TIME * 24 * 60 * 60 * 1000),
    httpOnly: true,
  };

  // if(process.env.NODE_ENV === 'production ') {
  //     options.secure = true;
  // }

  res.status(statusCode).cookie("token", token, options).json({
    success: true,
    token,
    expire: process.env.COOKIE_EXPIRES_TIME,
  });
};

const getJwtToken = (user) => {
  return jwt.sign({ username: user.username }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_TIME,
  });
};
