# Changelog

## 1.2

### Logs
- **One log per character**, `logs\chathistoryplus\<Name>_<id>\chathistoryplus.log`; lines from before login move into it at login.
- **Several clients can share one Ashita folder** without losing or overwriting each other's lines (reported by
  Fel-FFXI, ChatHistoryPlus pull request #1).
- **Each log keeps its newest 1 MB**; no `.old` files.
- **`diag` writes its report into your character's log** instead of a separate file.
- Every failure says so once in chat and names the log.
- A load writes one line for the 13 signatures instead of the whole table (the table is in `diag`, and in the log whenever one fails).
- The update deletes the old files: `logs\chathistoryplus\chathistoryplus.log`, `logs\chathistoryplus\chathistoryplus.log.old` and `logs\chathistoryplus_diag.log`.

### Unloading and safety
- **`/unload` then `/load` works in the same session, a new build included.** Unloading takes every change back out,
  and only then does ChatHistoryPlus leave memory, so nothing can jump into an unloaded copy. If something could not be
  put back, it stays in memory until the game closes, and a `/load` before then is refused.
- **Loaded after your chat log has started filling, it says it is off** until your next login, instead of saying
  nothing (it cannot switch over once a page has closed).
- **Every change to the game's code, and every change back, is made with the game's other threads paused,** at a
  moment when none of them is inside the code being changed or the plugin itself, so no thread is caught half-way
  through bytes that change. A failed install is rolled back in the same pass.
- **While the plugin is off, anything of it still in the game passes calls straight through** to the game's own code.
  If something cannot be put back (another tool rewrote the same bytes), it stays in that way and the plugin says so.
- Every change back is read back to confirm it: the outcome goes to chat, the reason to the log.
- Handing the history back to the game's own layout keeps the newest messages that fit its 16-bit table, instead of a
  flat 50 per page (the game reads those offsets as signed, so the limit is 32,767 bytes).
- The thread pause skips threads that have already exited. One kept alive by another handle used to make every pause
  fail, so ChatHistoryPlus never switched on.

## 1.1

- A record is one wrapped display line, and a single one can reach 2,047 bytes because colour codes
  cost bytes but no screen width. 140 of them do not fit a size the client tracks in a signed 16-bit
  field, which breaks past 32,767. The plugin now carries the size as 32-bit and raises the buffer
  ceiling to 128 KB.
- An eighth detour, on the page method that frees the text buffer. It is the only one that discards
  the buffer without going through the plugin, so without it the carried size outlived the
  allocation it described.
- Unloading now compacts the records it keeps to fresh low offsets. The native table is 16-bit, so an
  offset above 32,767 cannot be handed back at all.

## 1.0

Initial Release