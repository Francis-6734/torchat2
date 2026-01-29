//! HTTP request handlers

use axum::response::Html;

/// Serve the main index page
pub async fn index() -> Html<&'static str> {
    Html(include_str!("../public/index.html"))
}
