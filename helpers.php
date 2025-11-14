<?php

// Empêche injection SQL
function esc($str)
{
    global $connexion;
    return mysqli_real_escape_string($connexion, $str);
}
