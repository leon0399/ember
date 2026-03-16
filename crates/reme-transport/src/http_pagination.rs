use crate::TransportError;

pub(crate) fn validate_next_cursor(
    next_cursor: &str,
    previous_cursor: Option<i64>,
) -> Result<i64, TransportError> {
    let parsed = next_cursor.parse::<i64>().map_err(|_| {
        TransportError::ServerError(
            "Paginated fetch response returned an invalid next_cursor".to_string(),
        )
    })?;

    if parsed <= 0 {
        return Err(TransportError::ServerError(
            "Paginated fetch response returned an invalid next_cursor".to_string(),
        ));
    }

    if previous_cursor.is_some_and(|previous| parsed <= previous) {
        return Err(TransportError::ServerError(
            "Paginated fetch response returned a non-advancing next_cursor".to_string(),
        ));
    }

    Ok(parsed)
}
