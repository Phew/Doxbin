<!DOCTYPE html>
<?php 

include "connect/db.php";

if(!isset($_SESSION)) 
    { 
        session_start(); 
        

    } 

    if(isset($_POST) & !empty($_POST)){
        // PHP Form Validations
        if(empty($_POST['username'])){ $errors[]="User Name field is Required"; }else{
            // Check Username is Unique with DB query
    
            if (!filter_var($_POST['username'], FILTER_SANITIZE_STRING)) {
                $errors[] = "no special tags allowed in username";
            }
    
            $ch = strlen($_POST['username']);
            if ($ch > 20)
            {
                $errors[] = "username is to long.";
            }
    
            if ($ch < 2)
            {
                $errors[] = "username is to short.";
            }
    
            $sql = "SELECT * FROM users WHERE username=?";
            $result = $dbh->prepare($sql);
            $result->execute(array(strip_tags($_POST['username'])));
            $count = $result->rowCount();
            if($count == 1){
                $errors[] = "Username already exists";
            }
        }
        if(empty($_POST['email'])){ $errors[]="Email field is Required"; }else{
    
           
    
            $ch = strlen($_POST['email']);
            if ($ch < 2)
            {
                $errors[] = "email is to short.";
            }
    
            if ($ch > 40)
            {
                $errors[] = "email is to long.";
            }
    
            $pattern = '/^(?!(?:(?:\\x22?\\x5C[\\x00-\\x7E]\\x22?)|(?:\\x22?[^\\x5C\\x22]\\x22?)){255,})(?!(?:(?:\\x22?\\x5C[\\x00-\\x7E]\\x22?)|(?:\\x22?[^\\x5C\\x22]\\x22?)){65,}@)(?:(?:[\\x21\\x23-\\x27\\x2A\\x2B\\x2D\\x2F-\\x39\\x3D\\x3F\\x5E-\\x7E]+)|(?:\\x22(?:[\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x21\\x23-\\x5B\\x5D-\\x7F]|(?:\\x5C[\\x00-\\x7F]))*\\x22))(?:\\.(?:(?:[\\x21\\x23-\\x27\\x2A\\x2B\\x2D\\x2F-\\x39\\x3D\\x3F\\x5E-\\x7E]+)|(?:\\x22(?:[\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x21\\x23-\\x5B\\x5D-\\x7F]|(?:\\x5C[\\x00-\\x7F]))*\\x22)))*@(?:(?:(?!.*[^.]{64,})(?:(?:(?:xn--)?[a-z0-9]+(?:-+[a-z0-9]+)*\\.){1,126}){1,}(?:(?:[a-z][a-z0-9]*)|(?:(?:xn--)[a-z0-9]+))(?:-+[a-z0-9]+)*)|(?:\\[(?:(?:IPv6:(?:(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){7})|(?:(?!(?:.*[a-f0-9][:\\]]){7,})(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,5})?::(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,5})?)))|(?:(?:IPv6:(?:(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){5}:)|(?:(?!(?:.*[a-f0-9]:){5,})(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,3})?::(?:[a-f0-9]{1,4}(?::[a-f0-9]{1,4}){0,3}:)?)))?(?:(?:25[0-5])|(?:2[0-4][0-9])|(?:1[0-9]{2})|(?:[1-9]?[0-9]))(?:\\.(?:(?:25[0-5])|(?:2[0-4][0-9])|(?:1[0-9]{2})|(?:[1-9]?[0-9]))){3}))\\]))$/iD';
    
            $emailaddress = $_POST['email'];
    
            if (preg_match($pattern, $emailaddress) === 1) {
                // emailaddress is valid
                // Check Email is Unique with DB Query
                $sql = "SELECT * FROM users WHERE email=?";
                $result = $dbh->prepare($sql);
                $result->execute(array($_POST['email']));
                $count = $result->rowCount();
                if($count == 1){
                    $errors[] = "Email already exists";
                }
            }
            else {
                $errors[] = "Not a valid email";
            }
            
        }
        
        if(empty($_POST['password'])){ $errors[]="Password field is Required"; }else{
            // check the repeat password
            if(empty($_POST['confpass'])){ $errors[]="Repeat Password field is Required"; }else{
                // compare both passwords, if they match. Generate the Password Hash
                if($_POST['password'] == $_POST['confpass']){
                    // create password hash
                    // current supported hash (bycript)
                    $pass_hash = password_hash($_POST['password'], PASSWORD_DEFAULT);
                }else{
                    // Display Error Message
                    $errors[] = "Both Passwords Should Match";
                }
            }
        }
        
        try{
            // match token somewhat prevent's api abuse not really
            if (isset($_POST['_token'])){
                if(isset($_SESSION['token'])){
                    if (empty($_POST['_token'])){
                        $errors[] = "Token Empty";
                        die(header("location: ../"));
                    }
                    if (!$_POST['_token'] == $_SESSION['token']){
                        $errors[] = "Token Error";
                        die(header("location: ../"));
                    }
                } else{
                    die();
                }
        
            } else {
                $errors[] = "Token Error";
                die();
            }
        } catch (Exception $e){
            $errors[] = "Token Error";
            die();
        }

        if(empty($errors)){
                $id = $dbh->lastInsertID();
                $sql = "INSERT INTO users (id, username, email, password, rank) VALUES (:id, :username, :email, :password, :rank)"; 
                $result = $dbh->prepare($sql);
                $values = array(':username'     => strip_tags($_POST['username']),
                                    ':email'        => strip_tags($_POST['email']),
                                    ':password'     => $pass_hash,
                                    ':rank'         => 0,
                                    ':id'           => $id
                                    );
                $res = $result->execute($values);
        }
        if ($res){
            $messages[] = "Registered Account";
        }
    
    
    }
?>
<html lang="en">
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta name="robots" content="noindex">
	
    <title>Register - Doxbin</title>
    <link rel="stylesheet" href="https://doxbin.org/legacy/index.css">
    <link href="//netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.css" rel="stylesheet">
	<style>
    .register-div{
        margin: 0 auto;
        max-width: 500px;
        min-width: 100px;
        width: 100%;
        text-align: left;
    }
    .register-div label{
        padding: 10px 0px 1px 3px;
        margin: 0;
    }
	input{
		line-height: 1.2;
		color: white;
		background: #282828;
		border: 0;
		border-radius: 2px;
		display: inline-block;
		-webkit-font-smoothing: antialiased;
		outline: none;
		padding: 7px 5px;
        width: 100%;
	}
	input::placeholder{
		color: rgb(167, 167, 167);
	}
	input[type=submit]{
		line-height: 1.2;
		color: white;
		background: #282828;
		border: 0;
		border-radius: 2px;
		display: block;
		-webkit-font-smoothing: antialiased;
		outline: none;
		padding: 7px 5px;
        width: 90%;
        margin: 15px auto 50px auto;
	}
	input{
		font-size: 100%;
	}
	
	input[type=submit]:hover{
		color: white;
		background: #3d3d3d;
		text-decoration: none;
	}
	.center {
	  text-align: center;
	}
    .wcon{
        background-color: #1f1f1f;
        width: 100%;
        border-radius: 5px;
        margin: 0 0 20px;
        box-shadow: 0 1px 3px #0a0b0d;
        padding: 10px 20px;
        position: relative;
        display: inline-block;
        -webkit-box-shadow: inset 0px 0px 3px 0px rgba(0,0,0,0.75);
        -moz-box-shadow: inset 0px 0px 3px 0px rgba(0,0,0,0.75);
        box-shadow: inset 0px 0px 3px 0px rgba(0,0,0,0.75);
        text-align: right;
    }
    .wcon p{
        margin-bottom: 3px;
    }
	</style>
</head>

<body>
<input type="hidden" name="_token" value="paeQPPF4PwSbqKLYaVxavvNeFyHTtz8b2a8loCAF">
    <nav class="navbar navbar-default navbar-fixed-top">
    <div class="container">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand" href="../">Doxbin Remake</a>
        </div>
        <div id="navbar" class="collapse navbar-collapse">
            <ul class="nav navbar-nav">
            <li class="active"><a href="index.php">Home</a></li>
                <li><a href="/Doxbin-2.0/upload/index.php">Add Paste</a></li>
                <li><a href="/Doxbin-2.0/users.php">Users</a></li>
                            </ul>
            <div class="sidebar-right">
                                    <ul class="nav navbar-nav">
                        <li ><a href="/login.php">Login</a></li>
                        <li class="active"><a href="/register.php">Register</a></li>
                    </ul>
                            </div>
        </div>
    </div>
</nav>
    <div class="container" style="background-color: #111111; min-height: 100vh;-webkit-box-shadow: 0px 0px 7px 0px rgba(31,31,31,1);-moz-box-shadow: 0px 0px 7px 0px rgba(31,31,31,1);box-shadow: 0px 0px 7px 0px rgba(31,31,31,1);">
        <div class="col-md-12" style="margin-top: 10px;">
            <div class="col-md-12" style="margin-top: 80px;">
                <div align="center">
                    <h5 style="font-size: 25px;">Create Account</h5>
                    <p style="color:white;">Save your account info somewhere, if you forget it we will not reset it for you.</p>
                    <noscript><p style="color: red; padding: 0px 0px 10px 0px; text-align: center; margin: 0;">Doxbin requires JavaScript to function correctly.</noscript>
                </div>
            </div>
            <div class="col-md-6 col-md-offset-3 text-center">
                <div class="register-div">
                <?php
                        if(!empty($errors)){
                            foreach ($errors as $error) {
                                echo "<div id='error-msg' style='color: red; padding: 10px 0px 0px 0px; text-align: center; margin: 0;''>&nbsp;".htmlspecialchars($error)."</div>";
                            }
                            
                        }
                    ?>
                    <?php
                        if(!empty($messages)){
                           
                            foreach ($messages as $message) {
                                echo "<div id='' style='color: green; padding: 10px 0px 0px 0px; text-align: center; margin: 0;''>&nbsp;".htmlspecialchars($message)."</div>";
                            }
                            
                        }
                    ?>
                <div id="error-msg" style="color: red; padding: 10px 0px 0px 0px; text-align: center; margin: 0;"></div>
                <form action="register.php" method="POST" id="register-form">
                <label for="username">Username</label><br>
                <input type="hidden" name="_token" value="paeQPPF4PwSbqKLYaVxavvNeFyHTtz8b2a8loCAF">
                <input type="text" name="username" placeholder="Username" aria-label="username" required="" autofocus><br>
                <label for="username">Email</label><br>
                <input type="text" name="email" placeholder="Email" aria-label="email"  required="" autofocus><br>
                <label for="username">Password</label><br>
                <input type="password" name="password" placeholder="Password" aria-label="password" required="" autofocus><br>
                <label for="username">Confirm Password</label><br>
                <input type="password" name="confpass" placeholder="Repeat password" required="" autofocus><br><br>
                
                
        
                
                <input type="submit" value="Register">
                </form>
                </div>
            </div>
            
        </div>
    </div>
    <script src="https://doxbin.org/legacy/jquery.min.js"></script>
    <script src="https://doxbin.org/legacy/jquery-ui-1.10.3.custom.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>

</body>
</html>
