# vanity-hash

`vanity-hash` modifies files by adding or replacing bytes with a nonce so the resulting hash contains specific data.

```bash
vanity-hash -s dead -e BEEF document.txt
sha256sum document.txt
dead16546543ffff45f5ff4ff65f90234acfe50123984920401823901923beef
```

## Features

- **Fastest CPU Detection**: Automatically selects the fastest SIMD / hardware instruction set available at runtime:
  - **SHA-NI**: Hardware accelerated Intel / AMD SHA extensions.
  - **AVX2 + RORX**: Multi-round optimized vector pipelines with BMI2.
  - **AVX1 / SSE4.1**: Optimized fallback pipelines.
- **Multithreaded Search**: Scales automatically across all available CPU cores.
- **Incremental Pre-Hashing**: Precomputes SHA-256 state for unmodified prefix blocks, maintaining high mining throughput even on large input files.
- **4-Bit Boundary Matching**: Matches arbitrary hex prefix and suffix patterns (e.g. 1 nibble, 3 nibbles, 5 nibbles, etc.).
- **Custom Nonce Alphabets**: Constrain the generated nonce to printable ASCII, alphanumeric, numeric, lowercase, uppercase, or binary bytes.
- **Flexible Nonce Placement**:
  - `append` (default): appends to the end of the file.
  - `last`: overwrites the end of the file growing backwards (preserving overall file size).
  - `<number>`: overwrites a specific byte offset.

## Building

### Requirements
- GCC / Clang
- YASM (`yasm`)
- Make

### Build Command
```bash
make
```

The resulting binary will be created at `bin/vanity-hash`.

## Usage

```text
vanity-hash v0.0.0 Modifies a file with a nonce so its hash contains magic words

usage: vanity-hash <options> infile [outfile]

remarks:
  - when outfile is omitted, infile is overwritten!
  - 4-bit boundaries are supported, like --start-with 123
  - placing the nonce at the start of large files will make it unusably slow

options:
  -h --hash          Hashing algorithm to use. Default sha256 (only supported for now)
  -s --start-with    Hash needs to start with (4-bit boundaries supported). Example: --start-with 123
  -e --ends-with     Hash needs to end with (4-bit boundaries supported). Example: --ends-with cafe
  -a --alphabet      Allowed characters in the nonce: ascii (32-127), lower (a-z), upper (A-Z),
                     num (0-9), alphanum (a-Z,0-9), binary (default)
  -t --timeout       Give up after a number of seconds (default infinite)
  -o --nonce-offset  Nonce placement: 'append' (default), 'last' (overwrites the end of the file
                     growing backwards), or a byte offset number to overwrite a section in the file
  -n --nonce-size    Fixed size of the nonce in bytes. Default is a dynamic size.
```

## Examples

### 1. Basic Vanity Prefix Search
Find a nonce so that the file's SHA-256 hash starts with `deadBEEF`:
```bash
vanity-hash -s deadBEEF document.txt
```

Example output:
```text
vanity-hash v0.0.0 started with cpu mode sha
searching will take approx. 4.3G hashes
time running: 3s (estimated: 4s)
hashes searched: 3.1G (1033.3 MHash/sec)

Hash found: deadbeef16546543ffff45f5ff4ff65f90234acfe50123984920401823901923
```

### 2. Prefix and Suffix Match with 4-bit Boundaries
Match both a 3-nibble prefix `123` and a 4-nibble suffix `cafe`:
```bash
vanity-hash -s 123 -e cafe test.bin
```

### 3. Nonce Overwrite Mode (`last` / fixed offset)
Overwrite the last bytes of a binary without increasing its file size:
```bash
vanity-hash -s 0000 -o last firmware.bin firmware_out.bin
```

### 4. Restricted Character Set Nonces
Generate nonces containing only printable digits (`num`) or ASCII alphanumeric characters (`alphanum`):
```bash
vanity-hash -s beef -a alphanum -n 6 script.py
```

### 5. Timeout
Search for up to 10 seconds before aborting:
```bash
vanity-hash -s deadbeefcafebabe -t 10 input.dat output.dat
```

## Running Tests

Run the test suite:
```bash
./tests.sh
```