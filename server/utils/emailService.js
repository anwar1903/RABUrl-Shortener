const nodemailer = require('nodemailer');

const sendEmail = async (to, subject, text) => {
    const transporter = nodemailer.createTransport({
        secure: true,
        host: "smtp.gmail.com",
        port: 465,
        auth: {
            user: 'anwarbatcha190300@gmail.com',
            pass: `attb ncuo smvi rdoc`,
        },
    });

    const mailOptions = {
        from: 'anwarbatcha190300@gmail.com',
        to,
        subject,
        text,
    };

    await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;