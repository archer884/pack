pub fn main() {
    // Grab the first cmd line arg as our content.
    let source: Vec<_> = match std::env::args().nth(1) {
        Some(s) => s.chars().filter(|c| !c.is_whitespace()).collect(),
        None => {
            // Return early if the user screwed up.
            // Darn that user.
            println!("Try running pack with a sentence, e.g. `pack \"<sentence>\"`");
            return;
        },
    };

    // My middle_factors function returns both factors,
    // but as it happens I only need one of them.
    let (_, width) = middle_factors(source.len());

    // Behavior for the printer expression below is totally
    // different depending on if we're in a left or right
    // state. The purist in me feels guilty about this, but
    // the pragmatist told him to make like a function and 
    // cut out the side effects.
    let mut left_to_right = false;

    // This whole thing fails miserably if your sentence has 
    // a prime length.
    let rows = source.chunks(width)
        .map(|chunk| {
            // This is why l2r started off backwards--so I 
            // could flip it before the if expression I use
            // as a return value.
            left_to_right = !left_to_right;
            if left_to_right {
                chunk.iter().take(width).map(|&c| c).collect::<String>()
            } else {
                chunk.iter().rev().take(width).map(|&c| c).collect::<String>()
            }
        });

    // Because lazy.
    println!("1, 1");

    // Because also still lazy.
    for row in rows {
        println!("{}", row);
    }
}

/// Returns the "middle-iest" factors for a value.
///
/// Like, say, an input value of 12 or 16 should return a value of four. The 
/// idea being to choose a factor that can be multiplied with another factor 
/// near itself (including, possibly, itself) to get the result value.
///
/// For any two possible middle factors, we favor the larger.
fn middle_factors(n: usize) -> (usize, usize) {
    let root = (n as f64).sqrt();

    // This expression creates an iterator of factor-pairs
    // (e.g. (3,4) for 12) and folds over them, returning
    // the pair exhibiting the least absolute difference 
    // between the first and second value.
    match root == root.floor() {
        true => (root as usize, root as usize),
        false => (2..n)
            .filter(|&f| n % f == 0)
            .map(|f| (f, n / f))
            .take_while(|&(a,b)| a < b)
            .fold((1, n), |a,b| if diff(a) > diff(b) { b } else { a })
    }
}

/// Returns the absolute difference of two-tuple.
///
/// > Note: will panic with an arithmetic overflow if
/// > values.0 is larger than values.1
///
/// An earlier version of this function allowed for values to appear in any 
/// order by subtracting `min(values)` from `max(values)`, but when I realized
/// I could guarantee their relative sizes using the filter in `middle_factors()`,
/// I removed that code.
#[inline(always)]
fn diff(values: (usize, usize)) -> usize {
    values.1 - values.0
}

#[cfg(test)]
mod test {
    //! These tests simply establish that the `middle_factors()` function in the 
    //! main crate actually works.
    
    #[test]
    fn mf_12_is_4() {
        assert!((3, 4) == super::middle_factors(12));
    }

    #[test]
    fn mf_35_is_7() {
        assert!((5, 7) == super::middle_factors(35));
    }

    #[test]
    fn mf_16_is_4() {
        assert!((4, 4) == super::middle_factors(16));
    }
}
