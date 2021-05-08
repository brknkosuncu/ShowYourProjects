import express from 'express';

import { signin, signup, forgotPassword, resetPassword } from '../controllers/user.js';

const router = express.Router();

router.post('/signin', signin);
router.post('/signup', signup);
router.post("/forgotpassword", forgotPassword);
router.put("/resetpassword", resetPassword);


export default router;