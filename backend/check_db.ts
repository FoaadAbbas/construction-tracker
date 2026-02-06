import "dotenv/config";
import { UserModel } from "./src/models.js";
import mongoose from "mongoose";
import fs from "fs";

const LOG_FILE = "check_db_log.txt";

function log(msg: string) {
    console.log(msg);
    fs.appendFileSync(LOG_FILE, msg + "\n");
}

async function main() {
    fs.writeFileSync(LOG_FILE, "Starting DB check...\n");
    log("Connecting to DB...");

    // Try corrected URI
    const originalUri = process.env.MONGODB_URI;
    log(`Original URI: ${originalUri}`);

    // Attempt 1: Correct typo consturction -> construction
    const correctedUri = originalUri?.replace("consturction", "construction");
    log(`Trying corrected URI: ${correctedUri}`);

    try {
        await mongoose.connect(correctedUri!);
        log("Connected with corrected URI (construction)!");
    } catch (e: any) {
        log(`Failed with corrected URI (construction): ${e.message}`);

        // Attempt 2: construction-tracker
        const trackerUri = originalUri?.replace("consturction", "construction-tracker");
        log(`Trying tracker URI: ${trackerUri}`);
        try {
            await mongoose.connect(trackerUri!);
            log("Connected with tracker URI!");
        } catch (e3: any) {
            log(`Failed with tracker URI: ${e3.message}`);
            log("Trying original...");
            try {
                await mongoose.connect(originalUri!);
                log("Connected with original URI!");
            } catch (e2: any) {
                log(`Failed with original URI too: ${e2.message}`);
                process.exit(1);
            }
        }
    }

    log("Connected successfully.");

    log("Listing Users:");
    const users = await UserModel.find({}, { email: 1, username: 1, _id: 1, resetToken: 1, resetTokenExpiry: 1 }).lean();

    if (users.length === 0) {
        log("No users found.");
    } else {
        users.forEach((u: any) => {
            log(`User: ${u.username}, Email: ${u.email}, ID: ${u._id}`);
            if (u.resetToken) {
                log(`  Has Reset Token: Yes`);
                log(`  Expiry: ${u.resetTokenExpiry}`);
            }
        });
    }
    process.exit(0);
}

main();
