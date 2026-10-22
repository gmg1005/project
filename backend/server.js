const express = require('express');
const app = express();
const PORT = 3000;

const users = {
    1: { id: 1, username: "alice", role: "user", secret: "Alice의 정보: 전화번호 010-1111-2222" },
    2: { id: 2, username: "bob", role: "user", secret: "Bob의 정보: 전화번호 010-3333-4444" },
    3: { id: 3, username: "admin", role: "administrator", secret: "관리자 플래그: FLAG{idor_colab_success_777}" }
};

app.get('/api/user', (req, res) => {
    const userId = req.query.id;
    if (users[userId]) {
        res.json({ success: true, data: users[userId] });
    } else {
        res.status(404).json({ success: false, message: "사용자를 찾을 수 없습니다." });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
