<?php if( !isset($page) ) die("You cannot access this page directly"); ?>
<!-- See README.md for assistance -->
<!DOCTYPE html>
<html lang="en">
<head>
    <title>SignUp Manager</title>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">
</head>
<body>
<div class="container" style="margin-top:20px">
    <h1 class="text-center" style="margin:0;padding:0">SignUp Manager</h1>
    <?php if( count($errors) > 0 ){ ?>
    <div class="row">
        <div class="col-md-6 col-md-offset-3" style="margin-top:15px">
            <div class="alert alert-danger">
                <?php foreach( $errors as $e ){ ?>
                    <p class="text-center"><?php echo $e; ?></p>
                <?php } ?>
            </div>
        </div>
    </div>
    <?php } ?>

    <div class="row">
        <div class="col-md-6">
            <form method="post">
                <input type="hidden" name="action" value="login">
                <div class="panel panel-default">
                    <div class="panel-heading">Login</div>
                    <div class="panel-body">
                        <div><label>Username:</label></div>
                        <div><input class="form-control" name="username"></div>
                        <div style="margin-top:7px"><label>Password:</label></div>
                        <div><input type="password" class="form-control" name="password"></div>
                        <div style="margin-top:11px">
                            <input type="submit" class="btn btn-success pull-right" value="Login">
                        </div>
                    </div>
                </div>
            </form>
        </div>
        <div class="col-md-6">
            <form method="post">
                <input type="hidden" name="action" value="signup">
                <div class="panel panel-default">
                    <div class="panel-heading">Signup</div>
                    <div class="panel-body">
                        <div><label>Username:</label></div>
                        <div><input class="form-control" name="username"></div>
                        <div style="margin-top:7px"><label>Password:</label></div>
                        <div><input type="password" class="form-control" name="password"></div>
                        <div style="margin-top:7px"><label>Age:</label>
                            <select name="age">
                                <?php for( $i=0;$i<=120;$i++){ ?>
                                    <option value="<?php echo $i; ?>"><?php echo $i; ?></option>
                                <?php } ?>
                            </select>
                        </div>
                        <div style="margin-top:7px"><label>First Name:</label></div>
                        <div><input class="form-control" name="firstname"></div>
                        <div style="margin-top:7px"><label>Last Name:</label></div>
                        <div><input class="form-control" name="lastname"></div>
                        <div style="margin-top:11px">
                            <input type="submit" class="btn btn-success pull-right" value="Login">
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>
</body>
</html>
