<?php

error_reporting(0);
//ini_set("display_errors", 1);
//error_reporting(0);
$seed = file_get_contents("seed");
$flag = file_get_contents("flag");

class User {    

    private $id;
    private $username;
    private $password;
    private $showSource;
    private $color;
    
    function __construct($id) {
        $this->id = $id;
        $this->username = "guest";
        $this->password = "guest";
        $this->showSource = false;
        $this->color = "#FFFFFF";
    }
    
    public function getUsername() {
        return $this->username;
    }
    
    public function setUsername($username) {
        $this->username = $username;
    }

    public function getPassword() {
        return $this->password;
    }
    
    public function setPassword($password) {
        $this->password = $password;
    }

    public function getShowSource() {
        return $this->showSource;
    }
    
    public function setShowSource($showSource) {
        $this->showSource = $showSource;
    }
    
    public function getColor() {
        return $this->color;
    }
    
    public function setColor($color) {
        $this->color = $color;
    }
}

$userColor = "#FFFFFF";
$result = "Login Failed";

if(isset($_POST["login"])){
    if(isset($_COOKIE["cookie"])){
        $user = unserialize($_COOKIE["cookie"]);
        $user->setUsername($_POST["username"]);
        $user->setPassword($_POST["password"]);
        setcookie("cookie", serialize($user), [
            "expires"=>time() + (86400 * 30),
            "path"=>"/",
            "httponly"=>true,
            "samesite"=>"Strict"
        ]);
    }
}

if(isset($_COOKIE["cookie"])){
    $user = unserialize($_COOKIE["cookie"]);
    if($user->getShowSource()){
        highlight_file(__FILE__);
        die();
    }else{
        $userColor = $user->getColor();
        gmp_random_seed($seed);
        $rand = gmp_random_bits(100);
        $password = $flag . gmp_strval($rand);
        if($user->getUsername() == "admin"){
            if($user->getPassword() == $password){
                $result = $flag;
            }
        }
    }
}else{
    $rand = gmp_random_bits(100);
    $user = new User(gmp_strval($rand));
    setcookie("cookie", serialize($user), [
        "expires"=>time() + (86400 * 30),
        "path"=>"/",
        "httponly"=>true,
        "samesite"=>"Strict"
    ]);
}

echo "<!DOCTYPE html>
<html lang='en'>
<head>
    <title>Login Page</title>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <link rel='icon' type='image/png' href='images/icons/favicon.ico'/>
    <link rel='stylesheet' type='text/css' href='vendor/bootstrap/css/bootstrap.min.css'>
    <link rel='stylesheet' type='text/css' href='fonts/font-awesome-4.7.0/css/font-awesome.min.css'>
    <link rel='stylesheet' type='text/css' href='vendor/animate/animate.css'>
    <link rel='stylesheet' type='text/css' href='vendor/css-hamburgers/hamburgers.min.css'>
    <link rel='stylesheet' type='text/css' href='vendor/select2/select2.min.css'>
    <link rel='stylesheet' type='text/css' href='css/util.css'>
    <link rel='stylesheet' type='text/css' href='css/main.css'>
</head>
<body>
    <div class='bg-contact2'>
        <div class='container-contact2'>
            <div class='wrap-contact2' style=\"background: " . $userColor . ";\">
                <form method='POST' enctype='multipart/form-data' class='contact2-form validate-form'>
                    <span class='contact2-form-title' style='padding-bottom: 5%;'>
                        Login
                    </span>

                    <div class='wrap-input2 validate-input' data-validate='Username is required'>
                        <input class='input2' type='text' name='username'>
                        <span class='focus-input2' data-placeholder='USERNAME'></span>
                    </div>

                    <div class='wrap-input2 validate-input' data-validate = 'Password is required'>
                        <input class='input2' type='password' name='password'>
                        <span class='focus-input2' data-placeholder='PASSWORD'></span>
                    </div>
                    
                    <div class='container-contact2-form-btn'>
                        <div class='wrap-contact2-form-btn'>
                            <input type='submit' name='login' value='Login' class='contact2-form-btn'>
                        </div>
                    </div>
                </form><br>"
                . $result . 
            "</div>
        </div>
    </div>


    <script src='vendor/jquery/jquery-3.2.1.min.js'></script>
    <script src='vendor/bootstrap/js/popper.js'></script>
    <script src='vendor/bootstrap/js/bootstrap.min.js'></script>
    <script src='vendor/select2/select2.min.js'></script>
    <script src='js/main.js'></script>

    <script>
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());

      gtag('config', 'UA-23581568-13');
    </script>

</body>
</html>";

?>