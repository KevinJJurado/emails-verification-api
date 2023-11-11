const { getAll, create, getOne, remove, update, verifyCode, login, getLoggedUser, resetPassword, verifyCodeReset } = require('../controllers/user.controllers');
const express = require('express');
const verifyJWT = require('../utils/verifyJWT')

const userRouter = express.Router();

userRouter.route('/')
    .get(verifyJWT, getAll)
    .post(create);

userRouter.route('/verify/:code')
    .get(verifyJWT, verifyCode)

userRouter.route('/me')
    .get(verifyJWT, getLoggedUser)

userRouter.route('/login')
    .post(login)

userRouter.route('/reset_password')
    .post(resetPassword)

userRouter.route('/reset_password/:code')
    .post(verifyCodeReset)

userRouter.route('/:id')
    .get(verifyJWT, getOne)
    .delete(remove)
    .put(verifyJWT, update);



module.exports = userRouter;