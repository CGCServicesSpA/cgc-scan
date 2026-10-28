<?php
function cgc_handler(): void
{
    $name = htmlspecialchars($_GET['name'] ?? '', ENT_QUOTES, 'UTF-8');
    echo $name;
    $allowed = ['status' => 'true'];
    echo $allowed['status'];
}
