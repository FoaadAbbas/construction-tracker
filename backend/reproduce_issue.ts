import "dotenv/config";
import nodemailer from "nodemailer";
import fs from "fs";

const LOG_FILE = "reproduce_log.txt";

function log(msg: string) {
    console.log(msg);
    fs.appendFileSync(LOG_FILE, msg + "\n");
}

async function main() {
    fs.writeFileSync(LOG_FILE, "Starting reproduction...\n");

    log("Testing SMTP Configuration...");
    log(`SMTP_HOST: ${process.env.SMTP_HOST}`);
    log(`SMTP_PORT: ${process.env.SMTP_PORT}`);
    log(`SMTP_USER: ${process.env.SMTP_USER}`);

    if (!process.env.SMTP_PASS) {
        log("SMTP_PASS is missing!");
        return;
    }
    log(`SMTP_PASS is set (length): ${process.env.SMTP_PASS.length}`);

    const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 587,
        secure: false,
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
        debug: true, // Enable debug output
        logger: true // Log information to console
    });

    try {
        log("Verifying connection...");
        await transporter.verify();
        log("Connection verified successfully!");

        log("Sending test email...");
        const info = await transporter.sendMail({
            from: process.env.SMTP_USER,
            to: process.env.SMTP_USER, // Send to self
            subject: "Test Email from Reproduction Script",
            text: "If you receive this, email configuration is working correctly.",
        });

        log(`Email sent: ${info.messageId}`);
        log(`Preview URL: ${nodemailer.getTestMessageUrl(info)}`);
    } catch (error: any) {
        log(`Error occurred: ${error}`);
        if (error.code) log(`Error Code: ${error.code}`);
        if (error.command) log(`Error Command: ${error.command}`);
        if (error.response) log(`Error Response: ${error.response}`);
    }
}

main();
