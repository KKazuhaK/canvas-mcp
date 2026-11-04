# Canvas MCP Sync privacy policy

Last updated: November 3, 2026 · [Chinese version](PRIVACY.zh.md)

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
