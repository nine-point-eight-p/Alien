pub struct KeyDecoder();

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Key
{
	None,
	ESC,
	One,
	Two,
	Three,
	Four,
	Five,
	Six,
	Seven,
	Eight,
	Nine,
	Zero,
	Minus,
	Equal,
	BackSpace,
	Tab,
	Q,
	W,
	E,
	R,
	T,
	Y,
	U,
	I,
	O,
	P,
	LSB,
	RSB,
	Enter,
	LCTRL,
	A,
	S,
	D,
	F,
	G,
	H,
	J,
	K,
	L,
	Colon,
	SineglePoint,
	Point,
	LSHIFT,
	BackSlash,
	Z,
	X,
	C,
	V,
	B,
	N,
	M,
	Comma,
	Dot,
	Slash,
	RSHIFT,
	DPSTAR,
	LALT,
	Space,
    CAPS,
    MouseScrollDown = 0x150,
    MouseScrollUp,
    MouseLeft = 272,
    MouseRight,
    MouseMid,
}

impl KeyDecoder {
    pub fn decode(code : usize)->Result<Key, ()>{
        let rt = match code {
            1 => {Key::ESC}
            2 => {Key::One}
            3 => {Key::Two}
            4 => {Key::Three}
            5 => {Key::Four}
            6 => {Key::Five}
            7 => {Key::Six}
            8 => {Key::Seven}
            9 => {Key::Eight}
            10 => {Key::Nine}
            11 => {Key::Zero}
            12 => {Key::Minus}
            13 => {Key::Equal}
            14 => {Key::BackSpace}
            15 => {Key::Tab}
            16 => {Key::Q}
            17 => {Key::W}
            18 => {Key::E}
            19 => {Key::R}
            20 => {Key::T}
            21 => {Key::Y}
            22 => {Key::U}
            23 => {Key::I}
            24 => {Key::O}
            25 => {Key::P}
            26 => {Key::LSB}
            27 => {Key::RSB}
            28 => {Key::Enter}
            29 => {Key::LCTRL}
            30 => {Key::A}
            31 => {Key::S}
            32 => {Key::D}
            33 => {Key::F}
            34 => {Key::G}
            35 => {Key::H}
            36 => {Key::J}
            37 => {Key::K}
            38 => {Key::L}
            39 => {Key::Colon}
            40 => {Key::SineglePoint}
            41 => {Key::Point}
            42 => {Key::LSHIFT}
            43 => {Key::BackSlash}
            44 => {Key::Z}
            45 => {Key::X}
            46 => {Key::C}
            47 => {Key::V}
            48 => {Key::B}
            49 => {Key::N}
            50 => {Key::M}
            51 => {Key::Comma}
            52 => {Key::Dot}
            53 => {Key::Slash}
            54 => {Key::RSHIFT}
            55 => {Key::DPSTAR}
            56 => {Key::LALT}
            57 => {Key::Space}
            58 => {Key::CAPS}
            272 => {Key::MouseLeft}
            273 => {Key::MouseRight}
            274 => {Key::MouseMid}
            _ => return Err(())
        };
        Ok(rt)
    }

    pub fn convert(key : Key)->Result<char, ()> {
        match key {
            Key::A => {Ok('a')}
            Key::B => {Ok('b')}
            Key::C => {Ok('c')}
            Key::D => {Ok('d')}
            Key::E => {Ok('e')}
            Key::F => {Ok('f')}
            Key::G => {Ok('g')}
            Key::H => {Ok('h')}
            Key::I => {Ok('i')}
            Key::J => {Ok('j')}
            Key::K => {Ok('k')}
            Key::L => {Ok('l')}
            Key::M => {Ok('m')}
            Key::N => {Ok('n')}
            Key::O => {Ok('o')}
            Key::P => {Ok('p')}
            Key::Q => {Ok('q')}
            Key::R => {Ok('r')}
            Key::S => {Ok('s')}
            Key::T => {Ok('t')}
            Key::U => {Ok('u')}
            Key::V => {Ok('v')}
            Key::W => {Ok('w')}
            Key::X => {Ok('x')}
            Key::Y => {Ok('y')}
            Key::Z => {Ok('z')}
            Key::Enter => {Ok('\r')}
            Key::One => {Ok('1')}
            Key::Two => {Ok('2')}
            Key::Three => {Ok('3')}
            Key::Four => {Ok('4')}
            Key::Five => {Ok('5')}
            Key::Six => {Ok('6')}
            Key::Seven => {Ok('7')}
            Key::Eight => {Ok('8')}
            Key::Nine => {Ok('9')}
            Key::Zero => {Ok('0')}
            Key::Dot => {Ok('.')}
            Key::Colon => {Ok(';')}
            Key::SineglePoint => {Ok('\'')}
            Key::BackSlash => {Ok('\\')}
            Key::Comma => {Ok(',')}
            Key::Slash => {Ok('/')}
            Key::Space => {Ok(' ')}
            Key::Minus => {Ok('-')}
            Key::Equal => {Ok('=')}
            Key::Tab => {Ok('\t')}
            _ => {Err(())}
        }
    }

    pub fn key_type(value : usize)->Result<KeyType, ()> {
        match value {
            1 => Ok(KeyType::Press),
            0 => Ok(KeyType::Release),
            _ => Err(())
        }
    }
}

impl Key {
    pub fn from_code(code : usize)->Result<Key, ()> {
        let rt = match code {
            1 => {Key::ESC}
            2 => {Key::One}
            3 => {Key::Two}
            4 => {Key::Three}
            5 => {Key::Four}
            6 => {Key::Five}
            7 => {Key::Six}
            8 => {Key::Seven}
            9 => {Key::Eight}
            10 => {Key::Nine}
            11 => {Key::Zero}
            12 => {Key::Minus}
            13 => {Key::Equal}
            14 => {Key::BackSpace}
            15 => {Key::Tab}
            16 => {Key::Q}
            17 => {Key::W}
            18 => {Key::E}
            19 => {Key::R}
            20 => {Key::T}
            21 => {Key::Y}
            22 => {Key::U}
            23 => {Key::I}
            24 => {Key::O}
            25 => {Key::P}
            26 => {Key::LSB}
            27 => {Key::RSB}
            28 => {Key::Enter}
            29 => {Key::LCTRL}
            30 => {Key::A}
            31 => {Key::S}
            32 => {Key::D}
            33 => {Key::F}
            34 => {Key::G}
            35 => {Key::H}
            36 => {Key::J}
            37 => {Key::K}
            38 => {Key::L}
            39 => {Key::Colon}
            40 => {Key::SineglePoint}
            41 => {Key::Point}
            42 => {Key::LSHIFT}
            43 => {Key::BackSlash}
            44 => {Key::Z}
            45 => {Key::X}
            46 => {Key::C}
            47 => {Key::V}
            48 => {Key::B}
            49 => {Key::N}
            50 => {Key::M}
            51 => {Key::Comma}
            52 => {Key::Dot}
            53 => {Key::Slash}
            54 => {Key::RSHIFT}
            55 => {Key::DPSTAR}
            56 => {Key::LALT}
            57 => {Key::Space}
            58 => {Key::CAPS}
            272 => {Key::MouseLeft}
            273 => {Key::MouseRight}
            274 => {Key::MouseMid}
            _ => return Err(())
        };
        Ok(rt)
    }

    pub fn to_char(&self)->Result<char, ()> {
        match *self {
            Key::A => {Ok('a')}
            Key::B => {Ok('b')}
            Key::C => {Ok('c')}
            Key::D => {Ok('d')}
            Key::E => {Ok('e')}
            Key::F => {Ok('f')}
            Key::G => {Ok('g')}
            Key::H => {Ok('h')}
            Key::I => {Ok('i')}
            Key::J => {Ok('j')}
            Key::K => {Ok('k')}
            Key::L => {Ok('l')}
            Key::M => {Ok('m')}
            Key::N => {Ok('n')}
            Key::O => {Ok('o')}
            Key::P => {Ok('p')}
            Key::Q => {Ok('q')}
            Key::R => {Ok('r')}
            Key::S => {Ok('s')}
            Key::T => {Ok('t')}
            Key::U => {Ok('u')}
            Key::V => {Ok('v')}
            Key::W => {Ok('w')}
            Key::X => {Ok('x')}
            Key::Y => {Ok('y')}
            Key::Z => {Ok('z')}
            Key::Enter => {Ok('\r')}
            Key::One => {Ok('1')}
            Key::Two => {Ok('2')}
            Key::Three => {Ok('3')}
            Key::Four => {Ok('4')}
            Key::Five => {Ok('5')}
            Key::Six => {Ok('6')}
            Key::Seven => {Ok('7')}
            Key::Eight => {Ok('8')}
            Key::Nine => {Ok('9')}
            Key::Zero => {Ok('0')}
            Key::Dot => {Ok('.')}
            Key::Colon => {Ok(';')}
            Key::SineglePoint => {Ok('\'')}
            Key::BackSlash => {Ok('\\')}
            Key::Comma => {Ok(',')}
            Key::Slash => {Ok('/')}
            Key::Space => {Ok(' ')}
            Key::Minus => {Ok('-')}
            Key::Equal => {Ok('=')}
            Key::Tab => {Ok('\t')}
            _ => {Err(())}
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum KeyType {
    Press,
    Release,
}