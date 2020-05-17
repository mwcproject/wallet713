#[macro_export]
macro_rules! cli_message {
        () => {
            {
                use std::io::Write;
                use crate::common::{COLORED_PROMPT};
                print!("\r{}", COLORED_PROMPT);
                std::io::stdout().flush().unwrap();
            }
        };

        ($fmt_string:expr, $( $arg:expr ),+) => {
            {
                use std::io::Write;
                use crate::common::COLORED_PROMPT;
                print!("\r");
                print!($fmt_string, $( $arg ),*);
                print!("\n{}", COLORED_PROMPT);
                std::io::stdout().flush().unwrap();
            }
        };

        ($fmt_string:expr) => {
            {
                use std::io::Write;
                use crate::common::{COLORED_PROMPT};
                print!("\r");
                print!($fmt_string);
                print!("\n{}", COLORED_PROMPT);
                std::io::stdout().flush().unwrap();
            }
        };
    }
