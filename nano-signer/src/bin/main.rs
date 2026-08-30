#![no_std]
#![no_main]
#![deny(
    clippy::mem_forget,
    reason = "mem::forget is generally not safe to do with esp_hal types, especially those \
    holding buffers for the duration of a data transfer."
)]
#![deny(clippy::large_stack_frames)]

use core::fmt::Write as _;

use esp_hal::clock::CpuClock;
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::main;
use esp_hal::usb_serial_jtag::UsbSerialJtag;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// This creates a default app-descriptor required by the esp-idf bootloader.
// For more information see: <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

#[allow(
    clippy::large_stack_frames,
    reason = "it's not unusual to allocate larger buffers etc. in main"
)]
#[main]
fn main() -> ! {
    // generator version: 1.3.0
    // generator parameters: --chip esp32s3 -o esp32s3-wroom-1

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    // The following pins are used to bootstrap the chip. They are available
    // for use, but check the datasheet of the module for more information on them.
    // - GPIO0
    // - GPIO3
    // - GPIO45
    // - GPIO46
    // These GPIO pins are in use by some feature of the module and should not be used.
    let _ = peripherals.GPIO27;
    let _ = peripherals.GPIO28;
    let _ = peripherals.GPIO29;
    let _ = peripherals.GPIO30;
    let _ = peripherals.GPIO31;
    let _ = peripherals.GPIO32;

    // RGB LED is active-LOW (Level::High == off). Verify these GPIO numbers
    // against the official Nano ESP32 pinout before trusting them.
    let mut red = Output::new(peripherals.GPIO46, Level::High, OutputConfig::default());
    let mut green = Output::new(peripherals.GPIO0, Level::High, OutputConfig::default());
    let mut blue = Output::new(peripherals.GPIO45, Level::High, OutputConfig::default());
    // Polarity of the D13 user LED is not yet confirmed; use `?` to check it empirically.
    let mut orange = Output::new(peripherals.GPIO48, Level::High, OutputConfig::default());

    let mut usb_serial = UsbSerialJtag::new(peripherals.USB_DEVICE);

    loop {
        // read_byte() is non-blocking (returns Err(WouldBlock) when nothing is
        // waiting), so we just spin until a byte shows up.
        let Ok(byte) = usb_serial.read_byte() else {
            continue;
        };

        match byte {
            b'r' => red.toggle(),
            b'g' => green.toggle(),
            b'b' => blue.toggle(),
            b'o' => orange.toggle(),
            b'p' => pink
            b'x' => {
                red.set_high();
                green.set_high();
                blue.set_high();
                orange.set_high();
            }
            b'?' => {
                let _ = write!(
                    usb_serial,
                    "red={:?} green={:?} blue={:?} orange={:?}\r\n",
                    red.output_level(),
                    green.output_level(),
                    blue.output_level(),
                    orange.output_level(),
                );
                let _ = usb_serial.flush_tx();
            }
            _ => {}
        }
    }

    // for inspiration have a look at the examples at https://github.com/esp-rs/esp-hal/tree/esp-hal-v1.1.0/examples
}
