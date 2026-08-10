# ChatHistoryPlus v1.1 - A Bigger Native Chat Log for Ashita v4

Raises how much chat FFXI keeps, from 1000 messages per window to **2800**.

## Why this exists

FFXI stores chat as **pages of 50 records, 20 pages per chat window**. That is 1000 messages, and
once the twenty-first page is needed the oldest one is discarded.

The records-per-page figure is a constant in the client, in six places:

```
mov  r32, 50        ->        mov  r32, 140
```

Raising it multiplies the whole store, because the page count does not change - 20 pages of 140 is
2800 messages per window. The plugin also has to carry the widened pages itself, which is the part
that is not one byte; see [How It Works](#how-it-works).

## Requirements

- Ashita 4.3.1.2 (interface version 4.30) - the version ChatHistoryPlus was built and tested against.

## Installation

Copy `chathistoryplus.dll` into `Ashita-v4beta-main\plugins\`, then:

```
/load chathistoryplus
```

> If you load it partway through a session your chat log has usually already started filling, and it
> cannot switch over safely at that point. It arms itself and applies at your next login instead.
> See [Why it only switches at login](#why-it-only-switches-at-login).

## Commands

| Command | Description |
|---------|-------------|
| `/chathistoryplus status` | Whether it is on, and how much history is held |
| `/chathistoryplus diag` | Full report to `logs\chathistoryplus_diag.log` |

`/chp` for short.

## Why it only switches at login

The client finds record *N* by dividing: `page = idx / recordsPerPage`. That divisor is **one global
constant**, so changing it does not only affect new pages - it re-interprets every page that already
exists.

With seven pages already closed at 50 records, record 100 lives in page 2. Flip the divisor to 140
and the client looks for it in page 0, slot 100 - a slot that page does not have. That empty slot is
a **hole**, and the rebuild that draws your log stops dead when it reaches one. You would not lose a
line; you would lose everything past it.

So every page in the store has to hold exactly the same number of records - not "at least", exactly,
because it is the divisor for an index and not a capacity. The only moment that is guaranteed is when
the store is **empty**, which is true at login and, once the first page closes, never again that
session. The plugin waits for that moment by itself.

## What the numbers mean

`/chp status` reports one figure, and it is worth knowing what it counts:

```
Holding 2823 message(s) -- 20 stored page(s) + 23 live.
Both chat windows keep their own copy of that same history, so this is the figure
for each of them, not a total.
```

FFXI keeps a **complete, separate history per chat window**, and both windows receive every line
so the same message is stored twice, once in each. The figure is per window, not a total to be added up.

## How It Works

**Your chat stays where it always was.** The plugin does not store your messages - it stores a larger
index of them.

A chat page in the client is two things:

- an **offset table** - a fixed array of 50 entries at the front of the page object, where entry *i*
  says at which byte message *i* starts;
- a **text blob** - one buffer holding the actual text, with room for far more than 50 messages.

The messages live in the blob. The table is only an index into it.

### Why changing a constant is not enough

Six places in the client hold the number 50, and it is a **divisor**: the client finds a message by
computing `page = index / 50`. Patch those six to 140 and the arithmetic works perfectly at 140
records a page.

The problem is physical. The offset table is **50 entries embedded in the object**, and the fields
the client reads after it - the blob pointer, the blob size, the live count - sit at fixed offsets
its compiled code already knows. A 140-entry array would push all of them along and every instruction
reading them would land on the wrong thing.

So after the constants, the client can count to 140 and has nowhere to put entries 50-139.

### What the plugin holds

A **shadow table** per live page: the same kind of offsets, just 140 of them instead of 50, and held
as 32-bit values. It detours the eight client functions that touch the index or the text buffer - the
page constructor and destructor, append, resolve (the read path), recount, the two that load and save
page files, and the one that frees the buffer - so the client behaves as though its array were larger.
No message text is copied anywhere.

The text buffer has the same problem. The client tracks its size in a **signed 16-bit** field, so it
breaks past 32,767 bytes - and a single record can reach 2,047, because colour codes cost bytes but no
screen width. So the shadow carries the true size too, and the ceiling is raised to 128 KB. Without it a page fills before it holds 140 records and the rest
store empty - blank lines, and scrollback that stops dead.

Closed pages go to disk with a wider header, and the loader detects the header size when reading one
back, so a file written at 50 and a file written at 140 are both readable.

### Unloading

Not just un-patching. The live page is written back to the native 50-record layout, keeping the
**most recent** 50 records and reporting how many older ones would not fit; and the stored
140-record page files, which stock code cannot read, are dropped from the index rather than left for
it to walk into.

### Three things worth knowing, all stock behaviour

- It changes **nothing** about what is on screen. The chat window shows the same number of lines; you
  can simply scroll back much further.
- The page count stays at **20**. All the extra history comes from wider pages, not more of them.
- The oldest page is still discarded once the store is full - at 2800 messages instead of 1000.

## Version history

See **CHANGELOG.md**.

## Thanks

- **The Ashita Team** - atom0s, thorny, and the Ashita Discord community

## License

MIT - see **LICENSE**.
