# Changelog

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