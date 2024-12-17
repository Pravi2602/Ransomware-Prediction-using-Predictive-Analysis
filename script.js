const express = require('express');
const multer = require('multer');
const path = require('path');

const app = express();

// Configure multer to save files to the specified directory
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, '/Users/lavanya/Documents/ransom/uploads'); // Replace with your desired path
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});

const upload = multer({ storage: storage });

app.post('/upload', upload.single('file'), (req, res) => {
    // Handle the uploaded file
    console.log(req.file);
    res.send('File uploaded successfully!');
});

app.listen(3000, () => {
    console.log('Server listening on port 3000');
});