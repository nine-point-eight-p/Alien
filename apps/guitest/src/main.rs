#![no_std]
#![no_main]

#[macro_use]
extern crate Mstd;
extern crate alloc;

use embedded_graphics::{draw_target::DrawTarget, prelude::OriginDimensions};
use embedded_graphics::pixelcolor::Rgb888;
use embedded_graphics::prelude::{Drawable, Point, RgbColor, Size};
use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};
use embedded_graphics::primitives::Primitive;

use Mstd::io::{flush_frame_buffer, frame_buffer, get_char, VIRTGPU_LEN, VIRTGPU_XRES};

const INIT_X: i32 = 640;
const INIT_Y: i32 = 400;
const RECT_SIZE: u32 = 40;

pub struct Display {
    pub size: Size,
    pub point: Point,
    //pub fb: Arc<&'static mut [u8]>,
    pub fb: &'static mut [u8],
}

impl Display {
    pub fn new(size: Size, point: Point) -> Self {
        let fb = frame_buffer();
        println!(
            "Hello world from user mode program! 0x{:X} , len {}",
            fb.as_ptr() as usize, VIRTGPU_LEN
        );
        Self { size, point, fb }
    }
}

impl OriginDimensions for Display {
    fn size(&self) -> Size {
        self.size
    }
}

impl DrawTarget for Display {
    type Color = Rgb888;

    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
        where
            I: IntoIterator<Item=embedded_graphics::Pixel<Self::Color>>,
    {
        pixels.into_iter().for_each(|px| {
            let idx = ((self.point.y + px.0.y) * VIRTGPU_XRES as i32 + self.point.x + px.0.x)
                as usize
                * 4;
            if idx + 2 >= self.fb.len() {
                return;
            }
            self.fb[idx] = px.1.b();
            self.fb[idx + 1] = px.1.g();
            self.fb[idx + 2] = px.1.r();
        });
        flush_frame_buffer();
        Ok(())
    }
}

pub struct DrawingBoard {
    disp: Display,
    latest_pos: Point,
}

impl DrawingBoard {
    pub fn new() -> Self {
        Self {
            disp: Display::new(Size::new(1280, 800), Point::new(0, 0)),
            latest_pos: Point::new(INIT_X, INIT_Y),
        }
    }
    fn paint(&mut self) {
        Rectangle::with_center(self.latest_pos, Size::new(RECT_SIZE, RECT_SIZE))
            .into_styled(PrimitiveStyle::with_fill(Rgb888::RED))
            .draw(&mut self.disp)
            .ok();
    }
    fn unpaint(&mut self) {
        Rectangle::with_center(self.latest_pos, Size::new(RECT_SIZE, RECT_SIZE))
            .into_styled(PrimitiveStyle::with_fill(Rgb888::BLACK))
            .draw(&mut self.disp)
            .ok();
    }
    pub fn move_rect(&mut self, dx: i32, dy: i32) {
        self.unpaint();
        self.latest_pos.x += dx;
        self.latest_pos.y += dy;
        self.paint();
    }
}

const LF: u8 = 0x0au8;
const CR: u8 = 0x0du8;

#[no_mangle]
pub fn main() -> i32 {
    // let fb_ptr = framebuffer() as *mut u8;
    let mut board = DrawingBoard::new();
    let _ = board.disp.clear(Rgb888::BLACK).unwrap();
    for i in 0..20 {
        let c = get_char();
        if c == LF || c == CR {
            break;
        }
        board.latest_pos.x += i;
        board.latest_pos.y += i;
        board.paint();
    }
    0
}
