// Fixture: Express service with NoSQL injection
const express = require('express');
const { MongoClient } = require('mongodb');
const app = express();
app.use(express.json());

let db;
MongoClient.connect('mongodb://localhost:27017').then(client => {
    db = client.db('testdb');
});

// NoSQL injection sink
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.collection('users').findOne({ username, password });
    if (user) res.json({ ok: true, user: user.name });
    else res.status(401).json({ error: 'invalid' });
});

app.get('/api/users/:id', async (req, res) => {
    const user = await db.collection('users').findOne({ _id: req.params.id });
    res.json(user);
});

app.listen(3000);
