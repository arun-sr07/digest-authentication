const { generateToken } = require("../config/jwtToken");
const User=require("../models/userModel")
const asyncHandler=require("express-async-handler");
const validateMongoDbId = require("../utils/validateMongoId");

const createUser = asyncHandler(async (req, res) => {
  
    const email = req.body.email;
   
    const findUser = await User.findOne({ email: email });
  
    if (!findUser) {
     
      const newUser = await User.create(req.body);
      res.json(newUser);
    } else {
      throw new Error("User Already Exists");
    }
  });
  const loginUserCtrl = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    const findUser = await User.findOne({ email });
  if (findUser && (await findUser.isPasswordMatched(password))) {
    res.json({
        _id: findUser?._id,
        firstname: findUser?.firstname,
        lastname: findUser?.lastname,
        email: findUser?.email,
        mobile: findUser?.mobile,
        token: generateToken(findUser?._id),
      });
    }
    else{
        throw new Error("Invalid Credentials");

    }});
    const updatedUser = asyncHandler(async (req, res) => {
        const { id } = req.params;
        validateMongoDbId(id);
      
        try {
          const updatedUser = await User.findByIdAndUpdate(
            id,
            {
              firstname: req?.body?.firstname,
              lastname: req?.body?.lastname,
              email: req?.body?.email,
              mobile: req?.body?.mobile,
            },
            {
              new: true,
            }
          );
          res.json(updatedUser);
        } catch (error) {
          throw new Error(error);
        }
      });
      const getallUser = asyncHandler(async (req, res) => {
        try {
          const getUsers = await User.find()
          res.json(getUsers);
        } catch (error) {
          throw new Error(error);
        }
      });
      
      // Get a single user
      
      const getaUser = asyncHandler(async (req, res) => {
        const { id } = req.params;
        validateMongoDbId(id);
      
        try {
          const getaUser = await User.findById(id);
          res.json({
            getaUser,
          });
        } catch (error) {
          throw new Error(error);
        }
      });
      
      // Get a single user
      
      const deleteaUser = asyncHandler(async (req, res) => {
        const { id } = req.params;
        validateMongoDbId(id);
      
        try {
          const deleteaUser = await User.findByIdAndDelete(id);
          res.json({
            deleteaUser,
          });
        } catch (error) {
          throw new Error(error);
        }
      });
  module.exports={createUser,loginUserCtrl ,getallUser,
    getaUser,
    deleteaUser,
    updatedUser,};