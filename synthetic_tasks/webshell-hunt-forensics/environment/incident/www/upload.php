<?php
// simple upload portal (v1.2) - files land in uploads/
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $dst = 'uploads/' . basename($_FILES['avatar']['name']);
    move_uploaded_file($_FILES['avatar']['tmp_name'], $dst);
    header('Location: /index.html');
    exit;
}
?>
<html><body><h1>Profile upload</h1>
<form method="post" enctype="multipart/form-data">
<input type="file" name="avatar"><button type="submit">Upload</button>
</form></body></html>
