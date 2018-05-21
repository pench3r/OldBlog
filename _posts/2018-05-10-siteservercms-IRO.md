---
layout: post
title: "siteserver cms cookie 欺骗漏洞分析"
---

#### 0x00 前言 ####

- CMS版本:3.4.1 专业版  IIS/7.5
- 反编译的.dll的工具为：ILSpy

起因：由于合作方的一个站点被黑，经过一系列的响应工作后，检测发现到该cms的漏洞，所以打算分析分析该CMS的漏洞成因是什么。

siteserver cms以.net开发，使用的部署方式也是基于预编译的情况(核心代码都会编译成为dll存放在project目录下的Bin目录中，可以使用.net的反编译工具来查看源码)，本篇会梳理基本的.net web应用需要如何分析代码逻辑。

拿`siteserver cms`举例访问目录下的`siteserver/top.aspx`举例

	<%@ Page Language="C#" Inherits="SiteServer.BackgroundPages.GeneralTop" Trace="false"%>
	<%@ Register TagPrefix="bairong" Namespace="BaiRong.Controls" Assembly="BaiRong.Controls" %>
	<%@ Register TagPrefix="user" Namespace="UserCenter.Controls" Assembly="UserCenter.Pages" %>
	<%@ Register TagPrefix="site" Namespace="SiteServer.Controls" Assembly="SiteServer.Controls" %>

在aspx的页面开头出现的这几条指令，首先第一条代表该页面主要的处理逻辑(`SiteServer.BackgroundPages.GeneralTop`表示去站点目录下的Bin目录中的`SiteServer.BackgroundPages.dll`中的GeneralTop类的处理)；剩下几条命令功能大致相同，主要是注册用户自定义的Control；使用第三条来说明，引用的control定义在的文件为指定的Assembly即为`UserCenter.Pages.dll`文件，namespace为`UserCenter.Controls`，而TagPrefix定义的user为在该页面引用的别名：

	<user:custom type="style" runat="server"></user:custom>

就是引用UserCenter.Controls中的custom类，所以页面处理主要是基于第一条指令指定的类来处理，剩下页面中像上面引用control时再找对应的类来处理。

我们需要了解一下asp.net page life cycle

![web]({{ '/images/201805/siteserver_iro_0_1.png' | prepend: site.baseurl }})

执行顺序是从上至下.

![web]({{ '/images/201805/siteserver_iro_0_2.png' | prepend: site.baseurl }})

#### 0x01 漏洞复现与描述 ####

接着开始通过网上公开的漏洞来分析，漏洞主要利用方式是通过访问后台的功能时在cookie中加入以下字段和值

	SITESERVER.ADMINISTRATOR.USERNAME=admin

我们来测试向后台文件`siteserver/top.aspx?module=cms`发送请求并带上这个Cookie来检查

![web]({{ '/images/201805/siteserver_iro_1_1_1.png' | prepend: site.baseurl }})

可以看到我们请求后，发生了重定向，但是在响应中发现后台的功能其实已经成功访问了，只需要修改返回包(修改302 Found为200 OK)我们就可以顺利访问后台。测试如图

![web]({{ '/images/201805/siteserver_iro_1_2.png' | prepend: site.baseurl }})![web]({{ '/images/201805/siteserver_iro_1_3.png' | prepend: site.baseurl }})

添加cookie，并修改返回包，需要修改多个因为登入后台有很多页面的请求。但是后面测试发现不添加该cookie也可以访问后台，只是有些功能无法使用。

![web]({{ '/images/201805/siteserver_iro_1_4.png' | prepend: site.baseurl }})


成功登入后台。这些都是基于公网公开的漏洞信息

#### 0x02 漏洞分析 ####

因此我们开始找一个对应的后台文件来分析，这里使用`siteserver/main.aspx`

![web]({{ '/images/201805/siteserver_iro_2_1.png' | prepend: site.baseurl }})

首先会执行基类`BackgroundBasePage`中的重写的初始化函数OnInit

![web]({{ '/images/201805/siteserver_iro_2_2.png' | prepend: site.baseurl }})

通过代码分析，图中2处为关键点，首先通过`arg_3C_0 = AdminFactory.Instance.IsAuthenticated;`来判断是否授权，其中`AdminFactory.Instance`为`IAdminHandler handler`

![web]({{ '/images/201805/siteserver_iro_2_3.png' | prepend: site.baseurl }})

而`IAdminHandler`为`interface`

![web]({{ '/images/201805/siteserver_iro_2_4.png' | prepend: site.baseurl }})

因此需要查看它的实现类，查询到为AdminHandlerImpl(定义在`UserCenter.Provider.Admin.AdminHandlerImpl`)其中`IsAuthenticated`是通过以下语句来判断

![web]({{ '/images/201805/siteserver_iro_2_5.png' | prepend: site.baseurl }})

`AdminAuthenticationConfig.CookieName`为`SITESERVER.ADMINISTRATOR`

![web]({{ '/images/201805/siteserver_iro_2_6.png' | prepend: site.baseurl }})

而`CookieUtils.IsExists`是直接从`cookie`中读取

![web]({{ '/images/201805/siteserver_iro_2_7.png' | prepend: site.baseurl }})

因此我们在cookie中加上`SITESERVER.ADMINISTRATOR`不为空即可

测试如下图所示：

![web]({{ '/images/201805/siteserver_iro_2_8.png' | prepend: site.baseurl }})

bingo！我们成功登入后台，并且我们没有发生跳转。这里就和网上公开的产生了不同。因为网上测试的版本是普通版，这次测试的为专业版。

对于我们第一次漏洞演示的时候没有添加这个`cookie`时发生了跳转，但是还是看到了后台的页面，那是因为第二处的问题

![web]({{ '/images/201805/siteserver_iro_2_2.png' | prepend: site.baseurl }})

当判断为未授权时通过`PageUtility.RedirectToLoginPage()`来重定向，但是可以看到在重定向后，并没有中断`page event`处理的流程，类似于php中`header("location:")`的重定向没有`exit`同样的问题，这里也是漏洞关键所在。

此时发现的2个问题可以导致后台功能的访问，但是只有当我们修改`SITESERVER.ADMINISTRATOR.USERNAME`为特定的值才能正常使用后台功能例如`admin`。

接着我们通过`siteserver/top.aspx`文件来分析,主要分析的为`Page_Load`函数的最后一条

![web]({{ '/images/201805/siteserver_iro_2_10.png' | prepend: site.baseurl }})

这个就是我们登入后台后在右上角展示的名字，通过`AdminContext.Current.UserName`来传递，我们来检查这个值是如何初始化的

![web]({{ '/images/201805/siteserver_iro_2_11.png' | prepend: site.baseurl }})

可以看到`Current`为`new AdminContext(current)`来初始化，而UserName通过以下方式来初始化

![web]({{ '/images/201805/siteserver_iro_2_12.png' | prepend: site.baseurl }})

这里又通过`AdminFactory.Instance.UserName`来进行初始化，结合前面的信息直接查看`AdminHandlerImpl`中UserName是如何获取的

![web]({{ '/images/201805/siteserver_iro_2_13.png' | prepend: site.baseurl }})

其中`AdminAuthenticationConfig.CookieNameUserName`为

![web]({{ '/images/201805/siteserver_iro_2_14.png' | prepend: site.baseurl }})

这里我们可以清楚了解到我们传递的值最后传递到`AdminHandlerImpl`的属性`UserName`，我们观察`AdminHandlerImpl`中其他的获取管理员功能和信息的函数，都是通过UserName来入库查询的，这类我们可以确定为不安全对象的引用导致了越权的操作

    public IAdminInfo GetAdminInfo(string userName)
		{
			IAdminInfo result = null;
			IDbDataParameter[] commandParameters = new IDbDataParameter[]
			{
				base.GetParameter("@UserName", EDataType.NVarChar, 255, userName)
			};
			using (IDataReader dataReader = base.ExecuteReader("SELECT [UserName], [Password], [PasswordFormat], [PasswordSalt], [CreationDate], [LastActivityDate], [LastModuleID], [CountOfLogin], [CreatorUserName], [IsLockedOut], [PublishmentSystemID], [DisplayName], [Question], [Answer], [Email], [Theme] FROM bairong_Administrator WHERE [UserName] = @UserName", commandParameters))
			{
				if (dataReader.Read())
				{
					result = new AdminInfoImpl(dataReader.GetValue(0).ToString(), dataReader.GetValue(1).ToString(), EPasswordFormatUtils.GetEnumType(dataReader.GetValue(2).ToString()), dataReader.GetValue(3).ToString(), dataReader.GetDateTime(4), dataReader.GetDateTime(5), dataReader.GetValue(6).ToString(), dataReader.GetInt32(7), dataReader.GetValue(8).ToString(), TranslateUtils.ToBool(dataReader.GetValue(9).ToString()), dataReader.GetInt32(10), dataReader.GetValue(11).ToString(), dataReader.GetValue(12).ToString(), dataReader.GetValue(13).ToString(), dataReader.GetValue(14).ToString(), dataReader.GetValue(15).ToString());
				}
				dataReader.Close();
			}
			return result;
		}

至此整个漏洞就比较清晰，大致为：在访问后台功能时通过添加`Cookie：SITESERVER.ADMINISTRATOR=123`时可以绕过后台的跳转，如果不添加也可以不过需要手动修改302跳转以及html页面中的跳转；再通过添加`Cookie：SITESERVER.ADMINISTRATOR.USERNAME=admin`可以使用管理员的功能，进行webshell的获取。漏洞的关键在于使用验证的信息是直接从客户端传入的cookie中获取。

#### 0x03 总结 ####

分析关于.net的web应用时需要注意几点

- 了解整个request在.net中是如何处理的，需要关注页面的逻辑在哪里
- 如何查看.net应用的源码信息
- 对于aspx page中引用指令的理解，对应的源码在哪里
- 在查看源码时最容易困惑的地方是一些类的调用不明白其中的数据，以及接口的调用

把上述问题搞明白是基础，同时分析代码时需要根据漏洞来迅速找到突破点，可以正向分析，也可以逆向分析提高效率。

Keep Going!!! :P


参考：

- https://www.codeproject.com/Articles/73728/ASP-NET-Application-and-Page-Life-Cycle
- https://www.c-sharpcorner.com/UploadFile/8911c4/page-life-cycle-with-examples-in-Asp-Net/
