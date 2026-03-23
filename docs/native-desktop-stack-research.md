# Native Desktop Stack Research

**Date**: 2026-03-23
**Status**: Research / Decision Pending
**Context**: Evaluate technology stacks for a native desktop GUI for reme, replacing the current ratatui TUI client.

**Requirements**:
- Truly native or high-quality custom-rendered (no Electron, Tauri, or webview-based)
- Memory-safe (Rust-compatible)
- Cross-platform: Windows, macOS, Linux
- Suitable for a messaging app (chat bubbles, conversation list, input, notifications)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Cross-Platform Rust GUI Frameworks](#cross-platform-rust-gui-frameworks)
3. [Platform-Native Shells + Rust Core](#platform-native-shells--rust-core)
4. [Non-Rust Cross-Platform Toolkits](#non-rust-cross-platform-toolkits)
5. [Industry Examples](#industry-examples)
6. [Comparison Matrix](#comparison-matrix)
7. [Recommendation](#recommendation)

---

## Executive Summary

There are three viable approaches for reme's desktop GUI:

| Approach | Effort | Native Feel | Accessibility | Mobile Path |
|----------|--------|-------------|---------------|-------------|
| **Iced** (pure Rust) | Low | Custom-rendered | Incomplete | No |
| **Slint** (Rust + .slint DSL) | Low-Medium | Native-style themes | Good | Embedded only |
| **Platform-native shells + UniFFI** | High | 100% native | Excellent | Natural (Swift/Kotlin) |

**Short-term recommendation**: Iced for fastest path from TUI to GUI, single Rust codebase.
**Long-term recommendation**: Platform-native shells with UniFFI when mobile support is needed.

---

## Cross-Platform Rust GUI Frameworks

> **Key insight**: No Rust GUI framework uses native OS widgets across all platforms. Every cross-platform Rust GUI either draws its own widgets (Iced, Slint, egui, GPUI) or wraps a toolkit that also draws its own (GTK). True native widgets require platform-specific UI code (SwiftUI on macOS, WinUI on Windows) with a shared Rust core.

### Iced

- **Repository**: github.com/iced-rs/iced (~15k stars)
- **Rendering**: Custom via wgpu (GPU) or tiny-skia (CPU fallback). NOT native OS widgets.
- **Architecture**: Elm architecture — declarative, functional, message-driven
- **Platforms**: Windows, macOS, Linux
- **Maturity**: v0.14 (Dec 2025). Used by **COSMIC Desktop** (System76), a full desktop environment with ~200K lines of Rust, launched stable Dec 11, 2025.
- **Accessibility**: **Incomplete.** Issue [#552](https://github.com/iced-rs/iced/issues/552) open since Oct 2020. Does NOT support Windows Narrator per the [2025 Rust GUI survey](https://www.boringcactus.com/2025/04/13/2025-survey-of-rust-gui-libraries.html). IME/input methods added in 0.14.
- **License**: MIT
- **Messenger apps**: An Iced+Axum chat app (~4,235 LOC) exists as an educational project. ollama-chat-iced exists for LLM chat.

**Pros**: Pure Rust (no FFI), same language as reme-core, Elm architecture suits messaging well, COSMIC validates it at scale.
**Cons**: Accessibility gaps, custom-rendered (won't match OS look), no mobile target.

### Slint

- **Repository**: github.com/slint-ui/slint
- **Rendering**: Software renderer, GL, or Skia. Uses native-style themes to approximate platform look.
- **Architecture**: Declarative `.slint` markup DSL + Rust/C++/JS backend
- **Platforms**: Windows, macOS, Linux, embedded (MCU)
- **Maturity**: 1.x stable. Commercial company (SixtyFPS GmbH). Used by WesAudio (audio hardware), LibrePCB 2.0 (PCB design, migrating from Qt).
- **Accessibility**: **Good.** Windows Narrator works. Provides `accessible-role`, `accessible-label` properties. Some issues with text input + NVDA ([#8732](https://github.com/slint-ui/slint/issues/8732)).
- **License**: **Triple-licensed**: GPLv3 / Royalty-free (covers desktop, mobile, web — not just open source) / Commercial (required for embedded). The royalty-free tier covers reme's desktop use case regardless of license choice.

**Pros**: Best accessibility among Rust GUI frameworks, production-ready, native-feel themes, stable 1.x API, <300KiB runtime.
**Cons**: Separate `.slint` DSL to learn, no mobile (desktop/embedded only).

### gtk4-rs

- **Repository**: github.com/gtk-rs/gtk4-rs
- **Rendering**: Native GTK4 widgets
- **Platforms**: Linux (excellent, truly native GNOME), macOS/Windows (requires GTK runtime, looks non-native)
- **Maturity**: Very mature (GTK4 is battle-tested)
- **Accessibility**: Good (inherits GTK's AT-SPI accessibility)
- **License**: LGPL (via GTK)

**Pros**: Truly native on Linux, excellent accessibility, mature.
**Cons**: Looks foreign on macOS/Windows, requires GTK runtime installation on non-Linux, heavy dependency.

### GPUI (Zed editor)

- **Repository**: Part of github.com/zed-industries/zed
- **Rendering**: Custom GPU (Metal on macOS, Vulkan/DX elsewhere). Hybrid immediate/retained mode.
- **Maturity**: Powers Zed editor (production). ~15 community projects (launchers, terminal emulators, Redis GUIs). Still tightly coupled to Zed's codebase.
- **Accessibility**: Not documented; no known screen reader support.
- **License**: Apache 2.0 (GPUI); Zed itself is GPL

**Verdict**: Not recommended for external projects yet. API is Zed-centric.

### Floem (Lapce editor)

- **Repository**: github.com/lapce/floem
- **Rendering**: wgpu (vger/vello) or CPU (tiny-skia), Skia fallback
- **Architecture**: Reactive signals (Leptos-inspired), Flexbox/Grid via Taffy
- **Maturity**: Pre-1.0, active development
- **Accessibility**: Incomplete — lacks Narrator support per 2025 survey.
- **License**: Apache 2.0

**Verdict**: Promising but too early for production use.

### Freya

- **Repository**: github.com/marc2332/freya
- **Rendering**: Skia-based, fully custom. Own layout engine, event system, styling.
- **Architecture**: Was Dioxus-based (v0.1-0.3), v0.4+ uses own reactive core.
- **Maturity**: Pre-1.0, "not quite ready for serious use" per 2025 survey.
- **Accessibility**: Partial Windows Narrator support.
- **License**: MIT

**Verdict**: Watch for future, not ready today.

### Xilem (Linebender / Druid successor)

- **Status**: Heavy development, not production-ready.
- **Verdict**: Do not bet on it yet.

### egui

- **Repository**: github.com/emilk/egui (~27k stars — largest Rust GUI community)
- **Rendering**: Immediate-mode, custom-rendered (redraws every frame as textured triangles via wgpu)
- **Platforms**: Windows, macOS, Linux, Web, Android
- **Accessibility**: **Good** — AccessKit integration enabled by default in eframe, supports Windows and macOS screen readers.
- **License**: MIT OR Apache-2.0
- **Best for**: Debug UIs, tools, quick prototypes

**Verdict**: Surprisingly good accessibility via AccessKit. However, immediate-mode rendering means constant redraws (higher power usage) and complex layouts/rich text editing are harder. Not ideal for a polished consumer messaging app, but could work for a quick prototype.

### Makepad

- **Repository**: github.com/makepad/makepad (~6k stars)
- **Rendering**: Custom GPU (Metal, DX11, OpenGL, WebGL). Shader-based styling.
- **Platforms**: macOS, Windows, Linux, iOS, tvOS, Android, WASM
- **Maturity**: 1.0 released May 2025, but documentation is sparse.
- **Accessibility**: **Poor** — Windows Narrator could not see content in 2025 survey.
- **License**: MIT OR Apache-2.0

**Verdict**: Broad platform support including mobile, but poor accessibility and documentation. Called "built for the Makepad team" by the 2025 survey.

---

## Platform-Native Shells + Rust Core

This is the "1Password / Mullvad / Firefox" pattern: put everything except UI into a Rust core library, write thin platform-specific UI shells.

```
┌─────────────────────────────────────┐
│     Platform-Native UI Shell        │
│  ┌───────┐ ┌───────┐ ┌──────────┐  │
│  │SwiftUI│ │WinUI 3│ │  GTK4    │  │
│  │macOS  │ │Windows│ │  Linux   │  │
│  └───┬───┘ └───┬───┘ └────┬─────┘  │
│      │         │           │        │
│  ┌───▼─────────▼───────────▼─────┐  │
│  │     UniFFI / cbindgen         │  │
│  │     (FFI Bridge Layer)        │  │
│  └───────────┬───────────────────┘  │
│  ┌───────────▼───────────────────┐  │
│  │       reme-core (Rust)        │  │
│  │  identity, encryption,        │  │
│  │  transport, storage, outbox   │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### UniFFI (Mozilla)

- **Version**: v0.31.0 (January 2026)
- **Official targets**: Kotlin, Swift, Python, Ruby
- **Community targets**: C# (via `uniffi-bindgen-cs`), Go, JavaScript
- **Features**: Async Rust → native async (`async/await` in Swift, `suspend fun` in Kotlin), proc macro or UDL interface definitions
- **Production users**: Firefox (all platforms), Mozilla application-services
- **Kotlin Multiplatform**: Supported via Gobley (third-party)
- **C# maturity**: Community-maintained, less mature than Swift/Kotlin

### Per-Platform UI Options

| Platform | Best Native UI | Bridge to Rust | Maturity |
|----------|---------------|----------------|----------|
| **macOS** | SwiftUI / AppKit | UniFFI → Swift, or `swift-bridge` crate | High. Ghostty (Mitchell Hashimoto) uses this pattern. |
| **Windows** | WinUI 3 / WPF | C# shell + Rust `cdylib` via P/Invoke. WinUI 3 from pure Rust NOT yet practical (`windows-rs` doesn't fully support it). | Medium. Requires C# bridge layer. |
| **Linux** | GTK4 | gtk4-rs (direct Rust, no FFI needed) | High. |
| **iOS** | SwiftUI | UniFFI → Swift | High (same as macOS). |
| **Android** | Jetpack Compose | UniFFI → Kotlin | High. |

### `swift-bridge` crate

Dedicated Swift ↔ Rust bridge. Supports `String`, `Option<T>`, `Result<T, E>`, structs, classes, async functions, generics. Swift 6.0+ compatible. More ergonomic than UniFFI for macOS-only, but UniFFI wins when you also need Kotlin/Android bindings.

### Windows Reality Check

WinUI 3 from Rust is blocked on `windows-rs` (#2153). Practical path today:
1. **C# WinUI 3 shell** + Rust `cdylib` via P/Invoke — most pragmatic
2. **C++/WinRT bridge** — thin C++ layer hosting WinUI 3, calling Rust via C FFI
3. **Wait for `windows-rs` WinUI 3 support** — actively developed, timeline unclear

---

## Non-Rust Cross-Platform Toolkits

### Compose Multiplatform (JetBrains) + Rust via JNI

- **Rendering**: Skia-based via Skiko. **NOT native OS widgets** — draws everything itself, like Flutter.
- **Platforms**: Android, iOS (stable as of v1.8.0, May 2025), Desktop, Web
- **Rust bridge**: `jni-rs` crate, or UniFFI → Kotlin/JNA. JNI support in UniFFI proposed (#2672).
- **License**: Apache 2.0

**Verdict**: Not truly native rendering. If you accept Skia-rendered UI, compare against Iced/Slint which keep everything in Rust without JVM dependency.

### Flutter + Rust (via `flutter_rust_bridge`)

- **Rendering**: Skia/Impeller, fully custom-rendered. NOT native OS widgets.
- **Verdict**: Same trade-off as Compose Multiplatform. Adds Dart dependency. Not "true native."

---

## Industry Examples

| App | Rust Core | UI Layer | Bridge | Truly Native UI? |
|-----|-----------|----------|--------|-------------------|
| **1Password** | ~63% of codebase (crypto, sync, DB, business logic) | TypeScript/React (Electron-like) | Neon + Typeshare | **No** (web tech) |
| **Mullvad VPN** | Daemon + tunnel management | Electron (desktop), Kotlin (Android), Swift (iOS) | gRPC IPC, JNI, Swift FFI | **Partial** (mobile yes, desktop no) |
| **Firefox** | Sync engines, crypto, components | Native per-platform (Kotlin/Swift/XUL+JS) | UniFFI | **Yes** (mobile) |
| **Ghostty** | Terminal emulator core | SwiftUI (macOS), GTK4 (Linux) | C FFI / swift-bridge | **Yes** |
| **COSMIC Desktop** | Everything | Iced (custom-rendered) | N/A (pure Rust) | **No** (custom) |

**Ghostty** is the closest model to what reme could do: Zig core (analogous to Rust core) with SwiftUI on macOS and GTK4 on Linux, truly native UI on each platform.

---

## Comparison Matrix

| Criteria | Iced | Slint | Platform-Native + UniFFI | Compose MP + Rust |
|----------|------|-------|--------------------------|-------------------|
| **Native OS widgets** | No | No (mimics) | Yes | No |
| **Accessibility** | Poor | Good | Excellent | Varies |
| **Single codebase** | Yes (Rust) | Yes (Rust + .slint) | No (3 UI codebases) | Yes (Kotlin) |
| **Language** | Rust only | Rust + Slint DSL | Rust + Swift + C# + Rust | Rust + Kotlin + JNI |
| **Mobile path** | None | None | Natural (Swift/Kotlin) | Natural |
| **Initial effort** | Low | Low-Medium | High | Medium |
| **Maintenance effort** | Low | Low | High (3 UIs) | Medium |
| **License risk** | None (MIT) | Low (royalty-free covers desktop) | None | None |
| **Production validation** | COSMIC Desktop | WesAudio, LibrePCB | Firefox, Ghostty | JetBrains apps |
| **OS integration** (tray, notifications) | Basic | Basic | Full | Full |

---

## Recommendation

### For reme's current phase (research/prototype, small team):

**Primary: Iced**

- Zero FFI overhead — pure Rust, same ecosystem as reme-core
- Fastest path from TUI to GUI (single codebase, single language)
- COSMIC Desktop proves it handles complex, polished UIs at ~200K LOC scale
- Messenger UIs are inherently custom (chat bubbles, conversation lists, typing indicators) — native widgets matter less than in a file manager or settings app
- Accessibility is the main weakness; monitor progress driven by COSMIC's dependency

**Strong alternative: Slint** (if accessibility is a priority)

- Significantly better accessibility than Iced today (Narrator works out of the box)
- Native-feel themes approximate platform look
- Royalty-free license covers desktop use — licensing is not a blocker
- Stable 1.x API (less churn than Iced's pre-1.0)
- Separate `.slint` DSL is a minor learning curve but has good tooling (live preview, Figma import)

### When mobile support is needed:

**Transition to Platform-Native Shells + UniFFI**

- `reme-core` is already a clean API boundary — this architecture is natural
- UniFFI generates Swift + Kotlin bindings automatically
- macOS: SwiftUI + UniFFI or swift-bridge
- Windows: C# WinUI 3 shell + Rust cdylib (until windows-rs catches up)
- Linux: gtk4-rs (direct Rust, no FFI)
- iOS/Android: SwiftUI/Jetpack Compose + UniFFI

This transition can be incremental: start with Iced desktop, add mobile via UniFFI later, then optionally replace Iced with native shells per platform if warranted.

---

## Sources

- [2025 Survey of Rust GUI Libraries](https://www.boringcactus.com/2025/04/13/2025-survey-of-rust-gui-libraries.html)
- [Iced GitHub / Issues](https://github.com/iced-rs/iced)
- [Slint Documentation](https://slint.dev/)
- [UniFFI GitHub (v0.31.0)](https://github.com/mozilla/uniffi-rs)
- [swift-bridge GitHub](https://github.com/chinedufn/swift-bridge)
- [1Password: Rust in Production](https://serokell.io/blog/rust-in-production-1password)
- [1Password: Typeshare](https://1password.com/blog/typeshare-for-rust)
- [Mullvad VPN Architecture](https://deepwiki.com/mullvad/mullvadvpn-app)
- [COSMIC Desktop Launch](https://9to5linux.com/system76-launches-first-stable-release-of-cosmic-desktop-and-pop_os-24-04-lts)
- [egui GitHub](https://github.com/emilk/egui)
- [AccessKit GitHub](https://github.com/AccessKit/accesskit)
- [GPUI Website](https://www.gpui.rs/)
- [awesome-gpui](https://github.com/zed-industries/awesome-gpui)
- [Floem GitHub](https://github.com/lapce/floem)
- [Freya GitHub](https://github.com/marc2332/freya)
- [Makepad GitHub](https://github.com/makepad/makepad)
- [Gobley (UniFFI + Kotlin Multiplatform)](https://gobley.dev/)
- [flutter_rust_bridge GitHub](https://github.com/fzyzcjy/flutter_rust_bridge)
- [Rust in Production: 1Password Podcast](https://corrode.dev/podcast/s04e06-1password/)
- [windows-rs WinUI 3 (Issue #2153)](https://github.com/microsoft/windows-rs/issues/2153)
- [Compose Multiplatform 1.8.0](https://blog.jetbrains.com/kotlin/2025/05/compose-multiplatform-1-8-0-released/)
- [Integrating Rust and SwiftUI](https://dfrojas.com/software/integrating-Rust-and-SwiftUI.html)
- [Crossplatform Business Logic in Rust (idverse)](https://forgestream.idverse.com/blog/20251105-crossplatform-business-logic-in-rust/)
