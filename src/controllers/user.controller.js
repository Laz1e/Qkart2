const httpStatus = require("http-status");
const ApiError = require("../utils/ApiError");
const catchAsync = require("../utils/catchAsync");
const { userService } = require("../services");

/**
 * Get user details
 *  - Use service layer to get User data
 * 
 *  - Return the whole user object fetched from Mongo

 *  - If data exists for the provided "userId", return 200 status code and the object
 *  - If data doesn't exist, throw an error using `ApiError` class
 *    - Status code should be "404 NOT FOUND"
 *    - Error message, "User not found"
 *  - If the user whose token is provided and user whose data to be fetched don't match, throw `ApiError`
 *    - Status code should be "403 FORBIDDEN"
 *    - Error message, "User not found"
 *
 * 
 * Request url - <workspace-ip>:8082/v1/users/6010008e6c3477697e8eaba3
 * Response - 
 * {
 *     "walletMoney": 500,
 *     "address": "ADDRESS_NOT_SET",
 *     "_id": "6010008e6c3477697e8eaba3",
 *     "name": "crio-users",
 *     "email": "crio-user@gmail.com",
 *     "password": "criouser123",
 *     "createdAt": "2021-01-26T11:44:14.544Z",
 *     "updatedAt": "2021-01-26T11:44:14.544Z",
 *     "__v": 0
 * }
 * 
 *
 * Example response status codes:
 * HTTP 200 - If request successfully completes
 * HTTP 403 - If request data doesn't match that of authenticated user
 * HTTP 404 - If user entity not found in DB
 * 
 * @returns {User | {address: String}}
 *
 */
const getUser = catchAsync(async (req, res) => {
  let { userId } = req.params;
  console.log(userId);

  let result =await userService.getUserById(userId);
  
  if(!result) {
    throw new ApiError(httpStatus.NOT_FOUND, "User not found")
  }

  if(result.email != req.user.email){
    throw new ApiError(
      httpStatus.FORBIDDEN, "User not authorized to access this resource"
    );
  }
  res.status(200).json(result);
});


// const getAllUsers = async (req, res) => {
//   let result = await userService.getAllUsers();
//   res.json(result);
// }

const createUser = async (req, res) => {

  try {
    const body = req.body;
    const newUser = await userService.createUser(body);
    res.status(200).json(newUser);
  } catch (error) {
    throw new ApiError(200,"Emai already taken");
  }

}


module.exports = {
  getUser,
  // getAllUsers,
  createUser,
};
