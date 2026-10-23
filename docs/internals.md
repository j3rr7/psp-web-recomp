# Internals and debugging

This is the part of the documentation for working on the code: where things live, the tools for finding out why a game misbehaves, and the less obvious decisions behind the renderer.

## Layout

`profile/` is a PSPRecomp profile, linked into the framework as `PSPRecomp/profiles/web` by `scripts/setup.sh`. Its host code is in `profile/host`:

| File | What it does |
|---|---|
| `main.cpp` | Entry point for the browser build and the headless native runner |
| `kernel.cpp` | Threads, synchronization, memory, the display and the GE system calls |
| `devices.cpp` | Controller, audio channels and mixing, UMD, utility dialogs, misc kernel queries |
| `io.cpp`, `webfs.cpp` | File system; the disc is streamed over HTTP Range requests in the browser |
| `pgd.cpp` | Decrypts PGD (DRM) files that games set up with `sceIoIoctl` |
| `mpeg.cpp` | The movie player's ring buffer and stream bookkeeping (no decoding yet) |
| `sas.cpp`, `atrac.cpp` | Sound effect voices and ATRAC3+ music and speech |
| `ge.cpp` | GE display lists, vertex processing and a software rasterizer fallback |
| `ge_gl.cpp` | The WebGL2 / OpenGL ES 3 backend |
| `ge_worker.cpp` | Runs the GE on its own thread |

`profile/web/shell.html` is the page: status bar, resolution menu, touch controls, fullscreen and the AudioWorklet. Generated code goes to `profile/generated/<game>` and must never be committed.

The scripts each do one step, and `scripts/port.sh` chains them:

| Script | Step |
|---|---|
| `setup.sh` | Fetch PSPRecomp, apply `patches/`, install the Emscripten SDK, build the tools |
| `extract_iso.py` | Extract an ISO9660 image, optionally from inside a ZIP |
| `decrypt.sh` | Decrypt `EBOOT.BIN` with pspdecrypt or DecEboot, named by `PSP_DECRYPT` |
| `generate.sh` | Translate the executable to C++ with `psp_recomp` |
| `manifest.py` | List the disc for streaming |
| `build_web.sh`, `build_native.sh` | Build the page or the headless runner (`GEN_OPT` sets the optimization level of the generated code, `JOBS` the parallelism) |
| `serve.sh`, `serve.py` | Serve a build with Range support and cross-origin isolation |

## The native runner

The headless runner executes the same code as the page and is much easier to debug. Built with `scripts/port.sh <name> <disc> --native` or `scripts/build_native.sh <name>`, it takes:

```bash
build/native-<name>/profiles/web/pspweb_<name> games/<name>/root/EBOOT.BIN --disc games/<name>/root/disc \
    --gl 1 --frames 2400 --scale 3 --dump-every 600 --dump frames/f --press 930:4000:6 --wav out.wav
```

`--gl 1` renders with OpenGL ES through a surfaceless EGL context (without it the software rasterizer is used), `--dump` and `--dump-every` write frames as PPM images (`scripts/ppm2png.py` converts them), `--press frame:buttons:length` holds PSP buttons given in hex for some frames so you can walk through menus, `--stick frame:x,y:length` holds the analog stick (0 to 255, 128 is the centre) so you can walk somewhere, `--wav` records the audio mix and `--threads 0` keeps the GE on the main thread. Every 60 frames it prints primitive and triangle counts, GE time, draw calls and extra GPU passes. At the end it lists every guest thread with what it waits on, and a watchdog reports where the guest spins if no frame completes for five seconds.

## Environment variables

`PSPWEB_TRACE_HLE=1` logs every system call with its arguments and result. `PSPRECOMP_TRACE_ON_ERROR=1` prints the last dispatches when the guest crashes.

`PSPWEB_DUMP_FRAME=n` logs every primitive of frame n with its render state and writes the textures it decodes into `build/dump` (or `PSPWEB_DUMP_DIR`); `PSPWEB_SKIP_PRIMS=a-b,c-d` leaves those primitives out of every frame. Together they find the draw behind a broken effect quickly. Keep the first few primitives of a frame when bisecting, because they usually clear the screen, and without them every earlier frame shows through.

To get to a later level without playing there, run the native runner on a copy of the disc made of symbolic links (`cp -as`) in which the first level's files point at the later level's. That boots some levels straight into the action, though a level that expects to be entered from a particular place may not start.

`PSPWEB_PASS_FRAME=n` lists the extra GL passes of frame n: stencil and alpha syncing, pixel format reinterpretation and feedback copies. `PSPWEB_GE_PROFILE=1` times the GE's sections and breaks drawn pixels down by render target. `PSPWEB_NO_FLIP_THROTTLE=1` disables the frame swap throttle described below.

In the browser, `?profile` shows per-frame timings in the status bar and `?threads=0` keeps the GE on the main thread. Building with `PROFILING=ON scripts/build_web.sh ...` keeps function names in the WebAssembly, so browser profilers show C++ names.

## Notes on the implementation

**Frame swaps.** Some games, God of War among them, swap the framebuffer without waiting for the vertical blank and would render several frames per displayed one. `sceDisplaySetFrameBuf` therefore holds a thread that changes the framebuffer twice within one blank until the next one.

**Surfaces.** Each framebuffer the GE draws into becomes a GL texture and framebuffer object keyed by its VRAM offset, stride and pixel format. A draw at an address inside an existing surface with the same layout (games pack bloom chains side by side) uses that surface at an offset, and a texture fetched from such an address samples it directly, restricted to the texture's own rectangle so wrapping and clamping behave as on the PSP. When the same bytes are used as 32-bit and as 16-bit pixels, a shader reinterprets one surface into the other. VRAM is only synchronized when the CPU needs it: a block transfer that reads drawn pixels, a texture the CPU has to decode, or a copy into a drawn area.

**Stencil.** The PSP keeps the stencil buffer in the framebuffer's alpha channel. Stencil tests and operations run in a real stencil buffer, and stencil is copied into alpha (or alpha back into stencil after uploads) only where something reads it. The copies are limited to the rectangles that changed, to the stencil bits a surface can hold, and to a single clear when a rectangle set one value everywhere.

**Resolution.** Surfaces can be one to four times the PSP's size. Only whole multiples are offered because framebuffers sit inside each other at pixel offsets. Uploads and downloads go through a native-size staging framebuffer.

**The GE thread.** `sceGeListEnQueue` queues the list for the worker and returns; `sceGeListSync` and `sceGeDrawSync` block the guest thread, and while the guest waits the kernel lets real time pass instead of skipping ahead. The per-frame reset, presenting and resolution changes are queued too, so they stay in order with the lists. In the browser the main thread must not wait for the worker while it creates its WebGL context, because browsers need the main thread to answer during that step; the worker starts in the background and work queued meanwhile runs once it is ready.

**Uploads.** Firefox re-validates a whole index buffer after any change to it, so each draw gets a small index buffer from a rotating pool. Vertex data is re-specified for every draw, which mobile drivers handle far better than writes into a buffer the GPU may still be reading.

## Changes to PSPRecomp

`patches/` holds five commits on top of PSPRecomp, each with a description: a code generation loop on `jal` to import stubs, jumps to targets that are not translation unit entries, VFPU register numbers produced by data decoded as code, the `addi` instruction, the 16 KiB scratchpad at 0x00010000, functions only reachable through pointers (found by their prologue after a previous `jr ra`), and several VFPU instructions that were rejected before.
