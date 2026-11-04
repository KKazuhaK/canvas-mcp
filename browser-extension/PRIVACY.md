# Canvas MCP Sync privacy policy

Last updated: November 3, 2026

Canvas MCP Sync is a browser extension with one purpose: while you are signed
in to Canvas, it copies a read-only snapshot of your own Canvas data to a
Canvas MCP Portal that you choose, so that the apps you connect to that Portal
can answer questions about your courses.

## What the extension reads

It reads from the Canvas site you set in the extension, with your signed-in
Canvas session. Reads run in an open Canvas tab when there is one; otherwise
the extension's background makes the same requests, and the browser attaches
your Canvas session to them. If you are not signed in to Canvas, nothing is
read.

It reads only Canvas API paths built into the extension; the Portal chooses
the query options within those paths. They return:

- your profile (including your name and email address), courses, enrollments,
  grades and groups, and the names of your teachers;
- assignments, assignment groups and your own submission status and scores;
  modules, quizzes (descriptions only; it never starts or reads a quiz
  attempt), course front pages and discussion topics;
- announcements, calendar events, planner items and notes, and to-do items;
- your Canvas activity stream, which Canvas fills with recent items from your
  courses. **It can include previews of your Inbox conversations, discussion
  posts and comments written by other people, and notifications, with the
  names of their authors.** Discussion topics and announcements likewise carry
  their authors' names and text.

It does not read file contents or class rosters, and it never changes anything
in Canvas.

## When it runs

When a Canvas page finishes loading (at most once every 10 minutes after a
successful sync, or once a minute while syncs are failing), every hour in the
background, and when you press **Sync now**.

## What it sends, and where

- The data above goes to the Portal address you enter in the extension, and
  nowhere else. Nothing is sent to the extension's developer unless the
  Portal you chose is run by the developer (see below).
- The extension does not read or send your Canvas password or cookies. It has
  no `cookies` permission; uploads to the Portal are made without browser
  cookies, using an upload token the Portal issued when you paired.
- There is no analytics, advertising or tracking code in the extension.

## What it keeps in your browser

`chrome.storage.local` (or Firefox's equivalent) holds the Portal and Canvas
addresses, the upload token, the time and outcome of the last sync, when each
Canvas path was last fetched, the ids of the courses last synced, and
short-lived pairing and retry state. Course
data itself is not kept in the browser after it is uploaded.

**Disconnect** in the extension clears all of this and asks the Portal to
delete what it holds. If the Portal cannot be reached, or the extension was
already disconnected, use "Disconnect and delete synced data" on the Portal's
Browser extension page instead. Removing the extension clears the browser side.

## What the Portal does with it

The Portal is run by whoever operates it, and its own privacy policy applies.
The Canvas MCP Portal software:

- encrypts snapshots at rest with the Portal's own key (the Portal's operator
  can technically decrypt them);
- uses them only to answer requests made with your account, which means the
  apps you connect to the Portal (often AI assistants) receive the parts they
  ask for, at your request;
- by default stops using data older than 14 days and deletes it after 30 days;
- deletes all of it when you choose "Disconnect and delete synced data" on its
  Browser extension page, or when the operator deletes your account (ask them).

If you use the Portal at `canvas.mcp.kazuhahub.com`, it is operated by the
maintainer of this extension. The data is used only to answer your own
requests through the apps you connect. It is not sold, not used for
advertising, credit decisions or any purpose unrelated to that, and not
transferred to anyone else except as needed to answer those requests.

The use of information received from this extension adheres to the
[Chrome Web Store User Data Policy](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq),
including the [Limited Use](https://developer.chrome.com/docs/webstore/program-policies/limited-use)
requirements.

## Permissions

- `storage`: the settings and status above.
- `alarms`: the hourly sync.
- `scripting`: to run the read requests inside your open Canvas tab, and to
  read the pairing code from the Portal tab you opened.
- `activeTab`: to read the address of the tab you open the extension from, so
  it can fill in your Canvas address.
- Host access, requested when you set it up, for the Canvas and Portal
  addresses you enter only.

## Contact

Questions or requests: open an issue at
<https://github.com/KKazuhaK/canvas-mcp/issues>.

---

# Canvas MCP Sync 隐私政策

最后更新：2026 年 11 月 3 日

Canvas MCP Sync 浏览器扩展只做一件事：在你登录 Canvas 时，把你自己的 Canvas 数据以只读快照的形式复制到你选择的 Canvas MCP 门户，让你连接到该门户的应用能回答关于你课程的问题。

## 扩展读取什么

扩展用你已登录的 Canvas 会话，从你在扩展中设置的 Canvas 网站读取数据。有打开的 Canvas 标签页时，请求在该页面里发起；没有时由扩展后台发起同样的请求，浏览器会给这些请求带上你的 Canvas 会话。你没有登录 Canvas 时不读取任何内容。

扩展只访问内置的 Canvas API 路径，查询参数由门户在这些路径范围内决定。读取的内容包括：

- 你的个人资料（含姓名和邮箱）、课程、选课、成绩和小组，以及授课教师的姓名；
- 作业、作业分组以及你自己的提交状态和分数；单元、测验（只读说明，从不开始或读取作答）、课程首页和讨论话题；
- 公告、日历事件、计划项和笔记、待办事项；
- 你的 Canvas 动态。Canvas 会在其中放入你课程里的最新内容，**可能包含站内信会话的预览、其他人写的讨论帖和评论以及通知，并附带作者姓名。** 讨论话题和公告同样带有作者姓名和正文。

扩展不读取文件内容和班级名单，也从不修改 Canvas 中的任何内容。

## 什么时候运行

Canvas 页面加载完成时（同步成功后最多每 10 分钟一次，同步失败期间最多每分钟一次）、后台每小时一次，以及你点击 **Sync now** 时。

## 发送什么、发到哪里

- 上述数据只发送到你在扩展中填写的门户地址。除非你选的门户由扩展开发者运营（见下文），否则不会发给开发者。
- 扩展不读取、不发送你的 Canvas 密码或 Cookie。它没有 `cookies` 权限；上传到门户时不带浏览器 Cookie，只使用配对时门户签发的上传令牌。
- 扩展中没有任何统计、广告或追踪代码。

## 浏览器里保存什么

`chrome.storage.local`（或 Firefox 的对应存储）中保存门户和 Canvas 地址、上传令牌、上次同步的时间和结果、每个 Canvas 路径上次读取的时间、上次同步的课程编号，以及短期的配对和重试状态。课程数据本身上传后不会留在浏览器里。

在扩展中点 **Disconnect** 会清除这些内容，并请求门户删除它保存的数据。如果门户无法访问，或扩展之前已经断开，请到门户的“浏览器扩展”页面点“断开连接并删除已同步的数据”。卸载扩展会清除浏览器中的部分。

## 门户如何处理这些数据

门户由各自的运营者运行，适用其自己的隐私政策。Canvas MCP 门户软件：

- 用门户自己的密钥加密保存快照（门户运营者在技术上可以解密）；
- 只用这些数据回答以你的账户发出的请求，也就是说，你连接到门户的应用（通常是 AI 助手）会按你的请求拿到它们需要的部分；
- 默认超过 14 天的数据不再使用，超过 30 天删除；
- 你在“浏览器扩展”页面点“断开连接并删除已同步的数据”，或运营者删除你的账户（需联系运营者）时，全部删除。

如果你使用的是 `canvas.mcp.kazuhahub.com` 上的门户，它由本扩展的维护者运营。数据只用于通过你连接的应用回答你本人的请求；不出售，不用于广告、信用评估或任何无关用途，除回答这些请求所必需的之外不转交给任何人。

本扩展对所获取信息的使用遵守 [Chrome 网上应用店用户数据政策](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq)，包括其中的[“有限使用”](https://developer.chrome.com/docs/webstore/program-policies/limited-use)要求。

## 权限说明

- `storage`：保存上面列出的设置和状态。
- `alarms`：每小时同步一次。
- `scripting`：在你打开的 Canvas 页面里发起读取请求，以及从你打开的门户页面读取配对码。
- `activeTab`：读取你打开扩展时所在标签页的地址，用来自动填写 Canvas 地址。
- 网站访问权限：在设置时申请，只针对你填写的 Canvas 和门户地址。

## 联系方式

有问题或请求，请在 <https://github.com/KKazuhaK/canvas-mcp/issues> 提 issue。
