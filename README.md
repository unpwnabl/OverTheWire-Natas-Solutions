
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

[Level 0](/imgs/lvl0/screenshot.png)

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
Thus the next credentials are:
<details>
<summary>Name:</summary>

`natas1`
</details>
<details>
<summary>Password:</summary>

`0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq`
</details>

### Level 1 <a name="level1"></a>
Landing on the site, we see this:

[Level 1](/imgs/lvl1/screenshot.png)

Since we can't see the source code by simply right-clicking, there's a keyboard shortcut that will open the Developer Tools automatically: `<F12>`[^1]. <br> From there, inspecting the HTML code will give us the password:
```html
<html>
    <head>
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
Thus the next credentials are:
<details>
<summary>Name:</summary>

`natas2`
</details>
<details>
<summary>Password:</summary>

`TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI`
</details>

### Level 2 <a name="level2"></a>
Landing on the site, we see this:

[Level 2](/imgs/lvl2/screenshot.png)

Now that we are free from the constriction of no right-click, we can inspect the page freely. When we do, we find something peculiar:
```html
<html>
    <head>
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

[Index](/imgs/lvl2/index.png)

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
Thus the next credentials are:
<details>
<summary>Name:</summary>

`natas3`
</details>
<details>
<summary>Password:</summary>

`3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH`
</details>

### Level 3 <a name="level3"></a>
Landing on the site, we see this:

[Level 3](/imgs/lvl2/screenshot.png)

The same page as [Level 2](#level2). Again, inspecting it gives us nothing, except...
```html
<html>
    <head>
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
The phrase "Not even Google will find it this time..." may seem like a provocation, yet it reveals something interesting: the [Robots Exclusion Protocol](https://en.wikipedia.org/wiki/Robots.txt), a standard used by websites to indicate to visiting web crawlers and other web robots which portions of the website they are allowed to visit. That's why Google won't be able to find it... <br> Anyways, this protocol implies the existence of a `robots.txt` file somewhere in the server. In fact, we can find it immediatly in http://natas3.natas.labs.overthewire.org/robots.txt :
```
User-agent: *
Disallow: /s3cr3t/
```
Seems like web crawlers aren't allowed to access a hiddent path called `/s3cr3t/`. Thankfully we aren't crawlers, we're hackers, so we can visit it easily. In http://natas3.natas.labs.overthewire.org/s3cr3t we find another Apache index, displaying a `users.txt` file like before:

[Index](/imgs/lvl3/index.png)

Clicking the file gives us the password to the next level:
```
natas4:****
```
Thus the next credentials are:
<details>
<summary>Name:</summary>

`natas4`
</details>
<details>
<summary>Password:</summary>

`QryZXc2e0zahULdHrtHxzyYkj59kUxLQ`
</details>

### Level 4 <a name="level4"></a>
Landing on the site, we see this:

[Level 4](/imgs/lvl4/screenshot.png)

The site tells us it accepts only requests from a specific URL/webpage. To understand better what we are working with, let's do some theory:
> The web works by using protocols, in this case the [HTTP protocol](https://en.wikipedia.org/wiki/HTTP) (HyperText Transfer Protocol), which allows request-response communication between server and client. The request includes the request method, the requested URL and the protocol version. However, it can also include additional, potentially needed information, the _request headers_.

In this case, the header we're looking for is the _referer header_, which specifies where the request is coming from, and that's exactly what we need. <br>
Opening the Developer Tools[^1], we can access the Network tab, where if we reload, we can see the traffic generated after:

[Network](/imgs/lvl4/network.png)

We can then access the `index.php` request (which I'll refer to now as the main one), and see the various headers sent. Scrolling down, we can locate the "Referer" header, which shows the current website URL. We need to change it such that the request comes from the next level. <br>
A little quirk about Developer Tools, is that it allows us to create/modify custom headers to send out. We'll do just that in this level. Right-clicking on the main request, and selecting "Edit and Resend", brings us to an editor. The solution for this level can only be accessed by http://natas5.natas.labs.overthewire.org, so we need to add in the last empty box the name "Referer", and value of the URL. <br>
Once done, we can send it, and get a response. Viewing it raw, we get the solution of the level:
```html
<html>
    <head>
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

