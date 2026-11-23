import { Router } from "express";
import {
      register,
      refresh
} from "./auth.controller"

import { requireAuth } from "../../middlewares/requireAuth.middleware";


const router = Router();

router.post("/register", register);
router.post("/refresh", refresh);

export default router;