#[cfg(all(not(feature = "secp256k1"), not(feature = "k256")))]
compile_error!("At least one of the `secp256k1` or `k256` features must be enabled.");

mod arithmetic;
mod errors;
mod points;
mod scalars;

use points::*;
use scalars::*;

use std::{env, process};

fn usage() {
    println!("Usage:");
    println!("");
    println!("-- Scalar operations --");

    #[cfg(feature = "cli")]
    println!("  secp scalar gen                           Generate a random scalar.");
    println!("  secp scalar add <scalar> [<scalar>...]    Sum two or more scalars.");
    println!("  secp scalar mul <scalar> [<scalar>...]    Multiply two or more scalars.");
    #[cfg(any(feature = "k256", feature = "secp256k1-invert"))]
    println!(
        "  secp scalar inv <scalar>                  Multiplicative inverse of a scalar mod n."
    );
    println!("");
    println!("-- Point operations --");
    #[cfg(feature = "cli")]
    println!("  secp scalar gen                           Generate a random point.");
    println!("  secp point add <point> [<point>...]       Sum two or more points.");
    println!(
        "  secp point mul <point> [<scalar>...]      Multiply a point by one or more scalars."
    );
    println!("");
    println!("-- Formats --");
    println!("");
    println!("Points are represented in 65-byte compressed hex format. Example:");
    println!("");
    println!("  02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    println!("");
    println!("Scalars are represented in 32-byte hex format. Example:");
    println!("");
    println!("  e8c23ee3c98e040adea5dc92c5c381d6be93615f289ec2d505909657368a0c8f");
    println!("");
    println!("Prepending a minus sign '-' in front of a point or scalar will negate it. Example:");
    println!("");
    println!("  -02eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    println!("");
    println!("-- Special values --");
    println!("");
    println!("- The values '0', '1', or '-1' may be substituted for any scalar.");
    println!(
        "- The value 'G' may be substituted for any point to represent the secp256k1 base point."
    );
    println!("- The value '0' may be substituted for any point to represent the additive identity point (infinity).");
    println!("");
}

enum Error {
    Usage(String),
    Runtime(String),
}

fn main() {
    let argv: Vec<String> = env::args().collect();

    if argv.len() < 3 {
        usage();
        process::exit(1);
    }

    let result = match argv[1].as_str() {
        "scalar" => run_scalar_op(&argv[2..]),
        "point" => run_point_op(&argv[2..]),
        arg => {
            usage();
            eprintln!("invalid command '{arg}'");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        match e {
            Error::Usage(msg) => {
                usage();
                eprintln!("Error: {}", msg);
                process::exit(1);
            }
            Error::Runtime(msg) => {
                usage();
                eprintln!("Error: {}", msg);
                process::exit(2);
            }
        }
    }
}

fn parse_scalar(mut scalar_str: &str) -> Result<MaybeScalar, Error> {
    let is_neg = scalar_str.starts_with("-");
    if is_neg {
        scalar_str = &scalar_str[1..];
    }

    let scalar = match scalar_str {
        "0" => MaybeScalar::Zero,
        "1" => MaybeScalar::one(),
        v => v
            .parse::<MaybeScalar>()
            .map_err(|e| Error::Runtime(e.to_string()))?,
    };

    if is_neg {
        Ok(-scalar)
    } else {
        Ok(scalar)
    }
}

fn parse_point(mut point_str: &str) -> Result<MaybePoint, Error> {
    let is_neg = point_str.starts_with("-");
    if is_neg {
        point_str = &point_str[1..];
    }

    let point = match point_str {
        "0" => MaybePoint::Infinity,
        "G" => MaybePoint::Valid(Point::generator()),
        v => v
            .parse::<MaybePoint>()
            .map_err(|e| Error::Runtime(e.to_string()))?,
    };

    if is_neg {
        Ok(-point)
    } else {
        Ok(point)
    }
}

fn run_scalar_op(args: &[String]) -> Result<(), Error> {
    match args[0].as_str() {
        #[cfg(feature = "cli")]
        "gen" => {
            println!("{:x}", Scalar::random(&mut rand::thread_rng()));
        }

        "add" => {
            let mut sum: MaybeScalar = parse_scalar(
                args.get(1)
                    .ok_or_else(|| Error::Usage("missing scalar arguments".to_string()))?,
            )?;

            for arg in &args[2..] {
                sum += parse_scalar(arg)?;
            }
            println!("{:x}", sum);
        }

        "mul" => {
            let mut product: MaybeScalar = parse_scalar(
                args.get(1)
                    .ok_or_else(|| Error::Usage("missing scalar arguments".to_string()))?,
            )?;

            for arg in &args[2..] {
                product *= parse_scalar(arg)?;
            }

            println!("{:x}", product);
        }

        #[cfg(any(feature = "k256", feature = "secp256k1-invert"))]
        "inv" => {
            let v = parse_scalar(
                args.get(1)
                    .ok_or_else(|| Error::Usage("missing scalar argument".to_string()))?,
            )?
            .not_zero()
            .map_err(|_| Error::Runtime("cannot invert zero scalar".to_string()))?;

            println!("{:x}", Scalar::one() / v);
        }

        op => {
            return Err(Error::Usage(format!("unknown scalar operation '{op}'")));
        }
    };

    Ok(())
}

fn run_point_op(args: &[String]) -> Result<(), Error> {
    match args[0].as_str() {
        #[cfg(feature = "cli")]
        "gen" => {
            println!("{:x}", Scalar::random(&mut rand::thread_rng()) * G);
        }

        "add" => {
            let mut sum: MaybePoint = parse_point(
                args.get(1)
                    .ok_or_else(|| Error::Usage("missing point arguments".to_string()))?,
            )?;

            for arg in &args[2..] {
                sum += parse_point(arg)?;
            }
            println!("{:x}", sum);
        }

        "mul" => {
            let mut product = parse_point(
                args.get(1)
                    .ok_or_else(|| Error::Usage("missing point argument".to_string()))?,
            )?;

            for arg in &args[2..] {
                product *= parse_scalar(arg)?;
            }
            println!("{:x}", product);
        }

        op => {
            return Err(Error::Usage(format!("unknown point operation '{op}'")));
        }
    };

    Ok(())
}
