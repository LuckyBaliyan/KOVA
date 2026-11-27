import { Router } from "express";
import {
      register,
      refresh,
      login,
      logOut,
      getMe,
      googleCallback,
      googleStart
} from "./auth.controller"
import { requireAuth } from "../../middlewares/requireAuth.middleware";


const router = Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/logout", logOut);

//need requireAuth here to validate current logged in person
router.get("/getMe", requireAuth, getMe);


// Google OAuth endpoints
router.get("/google", googleStart);
router.get("/google/callback", googleCallback);

export default router;