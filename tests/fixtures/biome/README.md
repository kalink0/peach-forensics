# Biome / SEGB fixtures

## `minimal.segb2`

Synthetic SEGB v2 file with one `Written` record (payload `12 04 74 65 73 74`,
field 2 = `"test"`).

## `Device.Wireless.Bluetooth.segb1`

A real SEGB v1 stream file from a public test device:

- **Source:** Josh Hickman's public iOS 17 test image (iPhone 11, N104AP,
  iOS 17.3 / 21D50, upgraded from iOS 16), Cellebrite UFED full file system
  extraction of 2024-07-28, distributed via Digital Corpora
  (<https://digitalcorpora.org/>), whose images "are freely available and may
  be used without prior authorization or IRB approval".
- **Path in the extraction:**
  `filesystem1/private/var/mobile/Library/Biome/streams/restricted/Device.Wireless.Bluetooth/local/727555041769812`
- **Original file:** 1,048,576 bytes, SHA-256
  `cd9b8a6c4697e88ad53c33f7313eb77bcb93eb942d3501c141ea77509bf006bf`.
- **Change:** truncated to the first 440 bytes, the header's end-of-data
  offset. Every byte after it in the original is zero (pre-allocated space,
  never read by the v1 reader). Fixture SHA-256:
  `ef0cb9c35d1c1eeafe7067d4be3d34b4450b00458ee301a378a65325054c48b4`.
- **Content:** four records — two `Deleted` (state 3, zeroed payload,
  2024-01-21) and two `Written` (state 1, 2024-07-28): a Bluetooth device
  `08:65:18:75:5E:75` named "This Is’s AirPods" connecting and disconnecting.
- **Expected values** in `segb.rs`'s `decodes_the_real_device_segb1_fixture`
  are the output of CCL Forensics' reference reader `ccl_segb1.py` for this
  file.
