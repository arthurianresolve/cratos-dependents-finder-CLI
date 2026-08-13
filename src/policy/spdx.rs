use std::collections::BTreeSet;

#[derive(Debug, Eq, PartialEq)]
enum Expression {
    License(String),
    With(String, String),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}

impl Expression {
    fn accepted(&self, allow: &BTreeSet<String>, deny: &BTreeSet<String>) -> bool {
        match self {
            Self::License(license) => term_accepted(license, license, allow, deny),
            Self::With(license, exception) => {
                let term = format!("{license} WITH {exception}");
                term_accepted(&term, license, allow, deny)
            }
            Self::And(left, right) => left.accepted(allow, deny) && right.accepted(allow, deny),
            Self::Or(left, right) => left.accepted(allow, deny) || right.accepted(allow, deny),
        }
    }
}

fn term_accepted(
    term: &str,
    base_license: &str,
    allow: &BTreeSet<String>,
    deny: &BTreeSet<String>,
) -> bool {
    let denied = contains_ignore_ascii_case(deny, term)
        || (term != base_license && contains_ignore_ascii_case(deny, base_license));
    !denied && (allow.is_empty() || contains_ignore_ascii_case(allow, term))
}

fn contains_ignore_ascii_case(values: &BTreeSet<String>, needle: &str) -> bool {
    values
        .iter()
        .any(|value| value.eq_ignore_ascii_case(needle))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operator {
    And,
    Or,
    With,
}

#[derive(Debug, Eq, PartialEq)]
enum Token {
    Term(String),
    Operator(Operator),
    Open,
    Close,
}

pub(super) fn expression_accepted(
    expression: &str,
    allow: &BTreeSet<String>,
    deny: &BTreeSet<String>,
) -> Result<bool, String> {
    let tokens = tokenize(expression)?;
    let mut parser = Parser { tokens, index: 0 };
    let parsed = parser.parse_or()?;
    if parser.index != parser.tokens.len() {
        return Err("unexpected trailing SPDX expression token".to_owned());
    }
    Ok(parsed.accepted(allow, deny))
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let spaced = input.replace('(', " ( ").replace(')', " ) ");
    let mut tokens = Vec::new();
    for value in spaced.split_whitespace() {
        tokens.push(match value {
            "(" => Token::Open,
            ")" => Token::Close,
            "AND" => Token::Operator(Operator::And),
            "OR" => Token::Operator(Operator::Or),
            "WITH" => Token::Operator(Operator::With),
            value
                if value.eq_ignore_ascii_case("AND")
                    || value.eq_ignore_ascii_case("OR")
                    || value.eq_ignore_ascii_case("WITH") =>
            {
                return Err(format!("SPDX operator `{value}` must be uppercase"));
            }
            value => Token::Term(value.to_owned()),
        });
    }
    if tokens.is_empty() {
        return Err("SPDX expression is empty".to_owned());
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    index: usize,
}

impl Parser {
    fn parse_or(&mut self) -> Result<Expression, String> {
        let mut expression = self.parse_and()?;
        while self.consume_operator(Operator::Or) {
            expression = Expression::Or(Box::new(expression), Box::new(self.parse_and()?));
        }
        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<Expression, String> {
        let mut expression = self.parse_with()?;
        while self.consume_operator(Operator::And) {
            expression = Expression::And(Box::new(expression), Box::new(self.parse_with()?));
        }
        Ok(expression)
    }

    fn parse_with(&mut self) -> Result<Expression, String> {
        let expression = self.parse_primary()?;
        if !self.consume_operator(Operator::With) {
            return Ok(expression);
        }
        let Expression::License(license) = expression else {
            return Err("SPDX WITH must follow a license identifier".to_owned());
        };
        let Some(Token::Term(exception)) = self.tokens.get(self.index) else {
            return Err("SPDX WITH must be followed by an exception identifier".to_owned());
        };
        let exception = exception.clone();
        self.index += 1;
        Ok(Expression::With(license, exception))
    }

    fn parse_primary(&mut self) -> Result<Expression, String> {
        match self.tokens.get(self.index) {
            Some(Token::Term(value)) => {
                self.index += 1;
                Ok(Expression::License(value.clone()))
            }
            Some(Token::Open) => {
                self.index += 1;
                let expression = self.parse_or()?;
                if !matches!(self.tokens.get(self.index), Some(Token::Close)) {
                    return Err("unclosed SPDX expression parenthesis".to_owned());
                }
                self.index += 1;
                Ok(expression)
            }
            Some(_) => Err("expected an SPDX license identifier".to_owned()),
            None => Err("unexpected end of SPDX expression".to_owned()),
        }
    }

    fn consume_operator(&mut self, expected: Operator) -> bool {
        if matches!(
            self.tokens.get(self.index),
            Some(Token::Operator(actual)) if *actual == expected
        ) {
            self.index += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn evaluates_spdx_and_or_and_with_semantics() {
        let allow = set(&[
            "MIT",
            "Apache-2.0",
            "GPL-2.0-only WITH Classpath-exception-2.0",
        ]);
        assert!(expression_accepted("MIT AND Apache-2.0", &allow, &BTreeSet::new()).unwrap());
        assert!(expression_accepted("GPL-3.0-only OR MIT", &allow, &BTreeSet::new()).unwrap());
        assert!(
            expression_accepted(
                "GPL-2.0-only WITH Classpath-exception-2.0",
                &allow,
                &BTreeSet::new()
            )
            .unwrap()
        );
        assert!(!expression_accepted("MIT AND GPL-3.0-only", &allow, &BTreeSet::new()).unwrap());
    }

    #[test]
    fn deny_overrides_an_allowed_term_without_rejecting_an_or_alternative() {
        let allow = set(&["MIT", "Apache-2.0"]);
        let deny = set(&["MIT"]);
        assert!(expression_accepted("MIT OR Apache-2.0", &allow, &deny).unwrap());
        assert!(!expression_accepted("MIT AND Apache-2.0", &allow, &deny).unwrap());
    }
}
