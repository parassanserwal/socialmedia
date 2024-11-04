const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());

const DATA_FILE = './data/users.json';
const POSTS_FILE = './data/posts.json';


const readData = (file) => JSON.parse(fs.readFileSync(file, 'utf-8'));
const writeData = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

const getUserByEmailOrMobile = (email, mobile) => {
    const users = readData(DATA_FILE);
    return users.find((u) => u.email === email || u.mobile === mobile);
};


app.post('/signup', async (req, res) => {
    const { name, email, mobile, password ,isPublic = true } = req.body;

    if (getUserByEmailOrMobile(email, mobile)) return res.status(400).send('User already exists');

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { id: uuidv4(), name, email, mobile, password: hashedPassword, role: 'registered',isPublic, followers: [], following: [] };

    const users = readData(DATA_FILE);
    users.push(newUser);
    writeData(DATA_FILE, users);

    res.status(201).send('User registered');
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = getUserByEmailOrMobile(email);

    if (!user) return res.status(400).send('User not found');
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(400).send('Invalid password');

    const token = jwt.sign({ id: user.id, role: user.role }, 'secret_key');
    res.json({ token });
});

const allowGuestForPublicAccounts = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    let userId;

    if (token) {
        try {
            const decoded = jwt.verify(token, 'secret_key');
            userId = decoded.id;
        } catch (err) {
            return res.status(401).send('Invalid token');
        }
    }

    req.userId = userId;
    next();
};
app.get('/users/:userId', allowGuestForPublicAccounts, (req, res) => {
    const { userId } = req.params;
    const users = readData(DATA_FILE);

    const user = users.find((u) => u.id === userId);
    if (!user) return res.status(404).send('User not found');

    
    if (!user.isPublic && !req.userId) {
        return res.status(403).send('This account is private. Login required to view.');
    }

    
    const profileData = {
        id: user.id,
        name: user.name,
        isPublic: user.isPublic,
        followers: user.followers.length,
        following: user.following.length,
    };

    res.json(profileData);
});

app.get('/posts', allowGuestForPublicAccounts, (req, res) => {
    const posts = readData(POSTS_FILE);
    const users = readData(DATA_FILE);

    
    const visiblePosts = posts.filter(post => {
        const author = users.find(user => user.id === post.authorId);
        return author && (author.isPublic || req.userId);
    });

    res.json(visiblePosts);
});

const auth = (role) => (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).send('Unauthorized');
    jwt.verify(token, 'secret_key', (err, decoded) => {
        if (err) return res.status(403).send('Forbidden');
        req.user = decoded;
        if (role && req.user.role !== role) return res.status(403).send('Access Denied');
        next();
    });
};


app.post('/posts', auth('registered'), (req, res) => {
    const { title, description } = req.body;
    const newPost = { id: uuidv4(), title, description, authorId: req.user.id, likes: 0, comments: [] };

    const posts = readData(POSTS_FILE);
    posts.push(newPost);
    writeData(POSTS_FILE, posts);

    res.status(201).send('Post created');
});

app.put('/posts/:id', auth('registered'), (req, res) => {
    const { id } = req.params;
    const { title, description } = req.body;
    const posts = readData(POSTS_FILE);
    const post = posts.find((p) => p.id === id && p.authorId === req.user.id);

    if (!post) return res.status(404).send('Post not found');
    post.title = title;
    post.description = description;
    writeData(POSTS_FILE, posts);

    res.send('Post updated');
});

app.post('/posts/:id/like', auth('registered'), (req, res) => {
    const { id } = req.params;
    const posts = readData(POSTS_FILE);
    const post = posts.find((p) => p.id === id);

    if (!post) return res.status(404).send('Post not found');
    post.likes += 1;
    writeData(POSTS_FILE, posts);

    res.send('Post liked');
});

app.post('/posts/:id/comment', auth('registered'), (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    const posts = readData(POSTS_FILE);
    const post = posts.find((p) => p.id === id);

    if (!post) return res.status(404).send('Post not found');
    post.comments.push({ id: uuidv4(), content, authorId: req.user.id });
    writeData(POSTS_FILE, posts);

    res.send('Comment added');
});


app.delete('/posts/:id/delete', auth('registered'), (req, res) => {
    const { id } = req.params;
    let posts = readData(POSTS_FILE);
    posts = posts.filter((p) => p.id !== id);
    writeData(POSTS_FILE, posts);

    res.send('Post deleted by admin');
});

// Follow a user
app.post('/follow/:targetUserId', auth('registered'), (req, res) => {
    const { targetUserId } = req.params;
    const users = readData(DATA_FILE);
    
    const follower = users.find((u) => u.id === req.user.id);
    const targetUser = users.find((u) => u.id === targetUserId);

    if (!targetUser) return res.status(404).send('User not found');
    if (targetUser.id === follower.id) return res.status(400).send("You can't follow yourself");


    if (follower.following.includes(targetUserId)) return res.status(400).send('Already following this user');


    follower.following.push(targetUserId);
    targetUser.followers.push(follower.id);

    writeData(DATA_FILE, users);
    res.send('User followed');
});


app.post('/unfollow/:targetUserId', auth('registered'), (req, res) => {
    const { targetUserId } = req.params;
    const users = readData(DATA_FILE);

    const follower = users.find((u) => u.id === req.user.id);
    const targetUser = users.find((u) => u.id === targetUserId);

    if (!targetUser) return res.status(404).send('User not found');

  
    if (!follower.following.includes(targetUserId)) return res.status(400).send('Not following this user');

    
    follower.following = follower.following.filter((id) => id !== targetUserId);
    targetUser.followers = targetUser.followers.filter((id) => id !== follower.id);

    writeData(DATA_FILE, users);
    res.send('User unfollowed');
});


app.get('/users/:userId/followers', (req, res) => {
    const { userId } = req.params;
    const users = readData(DATA_FILE);

    const user = users.find((u) => u.id === userId);
    if (!user) return res.status(404).send('User not found');


    const followers = users.filter((u) => user.followers.includes(u.id)).map(({ id, name }) => ({ id, name }));
    res.json({ followers });
});

app.get('/users/:userId/following', (req, res) => {
    const { userId } = req.params;
    const users = readData(DATA_FILE);

    const user = users.find((u) => u.id === userId);
    if (!user) return res.status(404).send('User not found');

    const following = users.filter((u) => user.following.includes(u.id)).map(({ id, name }) => ({ id, name }));
    res.json({ following });
});


app.listen(3000, () => console.log('Server running on http://localhost:3000'));
