<<<<<<< HEAD

=======
>>>>>>> ac754cc (Added solutions)
# OverTheWire Natas Solutions

This is a collection of solution for the [OverTheWire Natas](https://overthewire.org/wargames/natas/) problems. Please use these as hints to solve them yourself (unless you're stuck).
OverTheWire Natas is a collection of 33 levels, each dealing with the basics of web security. All of the levels are found at http://natasX.natas.labs.overthewire.org, where X is the level number.

## Levels
- [Level 0](#level0)
- [Level 1](#level1)
- [Level 2](#level2)
- [Level 3](#level3)
- [Level 4](#level4)
- [Level 5](#level5)
- [Level 6](#level6)

### Level 0 <a name="level0"></a>
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
<<<<<<< HEAD
Thus the next credentials are:
<details>
<summary>Name:</summary>

`natas1`
</details>
<details>
<summary>Password:</summary>

`0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq`
</details>
=======
>>>>>>> ac754cc (Added solutions)

### Level 1 <a name="level1"></a>
Landing on the site, we see this:

![Level 1](/imgs/lvl1/screenshot.png)

<<<<<<< HEAD
Since we can't see the source code by simply right-clicking, there's a keyboard shortcut that will open the Developer Tools automatically: `<F12>`[^1]. <br> From there, inspecting the HTML code will give us the password:
```html
<html>
    <head>
=======
Since we can't see the source code by simply right-clicking, there's a keyboard shortcut that will open the [Developer Tools](https://firefox-source-docs.mozilla.org/devtools-user/) automatically: `<F12>`[^1]. <br> From there, inspecting the HTML code will give us the password:
```html
<html>
    <head>
        ...
>>>>>>> ac754cc (Added solutions)
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
<<<<<<< HEAD
Thus the next credentials are:
<details>
<summary>Name:</summary>

`natas2`
</details>
<details>
<summary>Password:</summary>

`TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI`
</details>
=======
>>>>>>> ac754cc (Added solutions)

### Level 2 <a name="level2"></a>
Landing on the site, we see this:

![Level 2](/imgs/lvl2/screenshot.png)

Now that we are free from the constriction of no right-click, we can inspect the page freely. When we do, we find something peculiar:
```html
<html>
    <head>
<<<<<<< HEAD
=======
        ...
>>>>>>> ac754cc (Added solutions)
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
<<<<<<< HEAD
Thus the next credentials are:
<details>
<summary>Name:</summary>

`natas3`
</details>
<details>
<summary>Password:</summary>

`3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH`
</details>
=======
>>>>>>> ac754cc (Added solutions)

### Level 3 <a name="level3"></a>
Landing on the site, we see this:

![Level 3](/imgs/lvl2/screenshot.png)

The same page as [Level 2](#level2). Again, inspecting it gives us nothing, except...
```html
<html>
    <head>
<<<<<<< HEAD
=======
        ...
>>>>>>> ac754cc (Added solutions)
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
<<<<<<< HEAD
The phrase "Not even Google will find it this time..." may seem like a provocation, yet it reveals something interesting: the [Robots Exclusion Protocol](https://en.wikipedia.org/wiki/Robots.txt), a standard used by websites to indicate to visiting web crawlers and other web robots which portions of the website they are allowed to visit. That's why Google won't be able to find it... <br> Anyways, this protocol implies the existence of a `robots.txt` file somewhere in the server. In fact, we can find it immediatly in http://natas3.natas.labs.overthewire.org/robots.txt :
=======
The phrase "Not even Google will find it this time..." may seem like a provocation, yet it reveals something interesting: the [Robots Exclusion Protocol](https://en.wikipedia.org/wiki/Robots.txt):
> The Robots Exclusion Protocol is a standard used by websites to indicate to visiting web crawlers and other web robots which portions of the website they are allowed to visit. 

That's why Google won't be able to find it... <br> Anyways, this protocol implies the existence of a `robots.txt` file somewhere in the server. In fact, we can find it immediatly in http://natas3.natas.labs.overthewire.org/robots.txt :
>>>>>>> ac754cc (Added solutions)
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
<<<<<<< HEAD
Thus the next credentials are:
<details>
<summary>Name:</summary>

`natas4`
</details>
<details>
<summary>Password:</summary>

`QryZXc2e0zahULdHrtHxzyYkj59kUxLQ`
</details>
=======
>>>>>>> ac754cc (Added solutions)

### Level 4 <a name="level4"></a>
Landing on the site, we see this:

![Level 4](/imgs/lvl4/screenshot.png)

The site tells us it accepts only requests from a specific URL/webpage. To understand better what we are working with, let's do some theory:
> The web works by using protocols, in this case the [HTTP protocol](https://en.wikipedia.org/wiki/HTTP) (HyperText Transfer Protocol), which allows request-response communication between server and client. The request includes the request method, the requested URL and the protocol version. However, it can also include additional, potentially needed information, the _request headers_.

<<<<<<< HEAD
In this case, the header we're looking for is the _referer header_, which specifies where the request is coming from, and that's exactly what we need. <br>
=======
In this case, the header we're looking for is the [referer header](https://en.wikipedia.org/wiki/HTTP_referer), which specifies where the request is coming from, and that's exactly what we need. <br>
>>>>>>> ac754cc (Added solutions)
Opening the Developer Tools[^1], we can access the Network tab, where if we reload, we can see the traffic generated after:

![Network](/imgs/lvl4/network.png)

<<<<<<< HEAD
We can then access the `index.php` request (which I'll refer to now as the main one), and see the various headers sent. Scrolling down, we can locate the "Referer" header, which shows the current website URL. We need to change it such that the request comes from the next level. <br>
=======
We can then access the `index.php` request (which I'll refer to now as the main one), and see the various headers sent. Thus, we need to "create" a referer header specifically to mask our real one. <br>
>>>>>>> ac754cc (Added solutions)
A little quirk about Developer Tools, is that it allows us to create/modify custom headers to send out. We'll do just that in this level. Right-clicking on the main request, and selecting "Edit and Resend", brings us to an editor. The solution for this level can only be accessed by http://natas5.natas.labs.overthewire.org, so we need to add in the last empty box the name "Referer", and value of the URL. <br>
Once done, we can send it, and get a response. Viewing it raw, we get the solution of the level:
```html
<html>
    <head>
<<<<<<< HEAD
=======
        ...
>>>>>>> ac754cc (Added solutions)
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
<<<<<<< HEAD
Thus the next credentials are:
<details>
<summary>Name:</summary>

`natas5`
</details>
<details>
<summary>Password:</summary>

`0n35PkggAPm2zbEpOU802c0x0Msn1ToK`
</details>

### Level 5 <a name="level5"></a>

### Level 6 <a name="level6"></a>

[^1]: I'll be using FireFox, and some DevTools and shorcuts are different from one another, although they're mostly similar in functionality.

=======

### Level 5 <a name="level5"></a>
Landing on the site, we see this:

![Level 5](/imgs/lvl5/screenshot.png)

Similarly to the past level, here we need some kind of authorization to view the full page. But how can the website know we aren't allowed to access it? It must _store_ some kind of information that prevents us from viewing it... <br> 
The only way a site remembers something is via [cookies](https://en.wikipedia.org/wiki/HTTP_cookie):
> An HTTP cookie is a small block of data created by a web server while a user is browsing a website and placed on the user's computer or other device by the user's web browser.

Not only it's stored locally, but it's part of a request header. Now, opening the Network tab in the Developer Tools, and scrolling down, we see the cookie header is set to `loggedin=0`:

![Cookie](/imgs/lvl5/cookie.png)

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

### Level 6 <a name="level6"></a>
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

### Level 7 <a name="level7"></a>
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
So there is a path where the password is store. Yet how can we access it when there's no way to move around in a web server? Here comes in play the GET variable from earlier... <br>
For those who don't use Linux, or aren't familiar to its Shell syntax, to move around folders one can use the command `cd /path_to_folder/`, and to move out, simply `cd ..` where the double dots represent the parent directory to where you are. <br>
We can use this to out advantage to "escalate" the folder, and reach the desider path in `/etc/natas_webpass/natas8`. After trial and error, one can come up to an URL like this: <br>
`http://natas7.natas.labs.overthewire.org/index.php?page=../../../../etc/natas_webpass/natas8` <br>
And there, our password is shown.

### Level 8 <a name="level8"></a>
Landing on the site, we see this:

![Level 8](/imgs/lvl8/screenshot.png)

### Level 9 <a name="level9"></a>
Landing on the site, we see this:

![Level 9](/imgs/lvl9/screenshot.png)

### Level 10 <a name="level10"></a>
Landing on the site, we see this:

![Level 10](/imgs/lvl10/screenshot.png)

### Level 11 <a name="level11"></a>
Landing on the site, we see this:

![Level 11](/imgs/lvl11/screenshot.png)


[^1]: I'll be using FireFox, and some DevTools and shorcuts are different from one another, although they're mostly similar in functionality.
>>>>>>> ac754cc (Added solutions)
