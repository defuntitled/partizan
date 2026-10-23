//! Static masquerade: what a visitor without a valid token sees, over HTTPS and HTTP/3. Every
//! such request, the auth path included, is answered like an ordinary nginx-served site.

use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use proto::auth::web::{self, WebRequest};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest file served.
const MAX_FILE: u64 = 10 << 20;
/// Idle time before a keep-alive connection is closed.
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// Requests per HTTP/1.1 connection.
const MAX_REQUESTS: usize = 100;

const DEFAULT_INDEX: &str = "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome</title>\n</head>\n<body>\n<h1>It works.</h1>\n<p>This site is under construction.</p>\n</body>\n</html>\n";
const NOT_FOUND: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";
const NOT_ALLOWED: &str = "<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";

/// The site served to visitors.
#[derive(Debug, Clone)]
pub struct Site {
    dir: Option<PathBuf>,
    port: u16,
}

/// One response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// Status code.
    pub status: u16,
    /// `content-type`.
    pub content_type: &'static str,
    /// Body.
    pub body: Vec<u8>,
}

impl Site {
    /// Site from `dir` (a built-in placeholder page without one); `port` goes into `alt-svc`.
    pub fn new(dir: Option<PathBuf>, port: u16) -> Self {
        Self { dir, port }
    }

    /// The response to `method path`.
    pub fn page(&self, method: &str, path: &str) -> Page {
        if method != "GET" && method != "HEAD" {
            return html(405, NOT_ALLOWED);
        }
        let path = path.split(['?', '#']).next().unwrap_or("/");
        let Some(dir) = &self.dir else {
            return if path == "/" || path == "/index.html" {
                html(200, DEFAULT_INDEX)
            } else {
                html(404, NOT_FOUND)
            };
        };
        match read_file(dir, path) {
            Some((body, content_type)) => Page {
                status: 200,
                content_type,
                body,
            },
            None => html(404, NOT_FOUND),
        }
    }

    fn headers(&self, page: &Page) -> Vec<(&'static str, String)> {
        vec![
            ("server", "nginx".into()),
            ("date", http_date(SystemTime::now())),
            ("content-type", page.content_type.into()),
            ("content-length", page.body.len().to_string()),
            ("alt-svc", format!("h3=\":{}\"; ma=86400", self.port)),
        ]
    }

    /// HTTP/1.1 response bytes.
    pub fn http1(&self, page: &Page, head_only: bool, close: bool) -> Vec<u8> {
        let reason = match page.status {
            200 => "OK",
            404 => "Not Found",
            405 => "Not Allowed",
            _ => "Bad Request",
        };
        let mut out = format!("HTTP/1.1 {} {reason}\r\n", page.status);
        for (name, value) in self.headers(page) {
            out.push_str(&format!("{}: {value}\r\n", title_case(name)));
        }
        out.push_str(if close {
            "Connection: close\r\n\r\n"
        } else {
            "Connection: keep-alive\r\n\r\n"
        });
        let mut out = out.into_bytes();
        if !head_only {
            out.extend_from_slice(&page.body);
        }
        out
    }

    /// HTTP/3 response bytes: `HEADERS`, then the body in a `DATA` frame.
    pub fn h3(&self, page: &Page, head_only: bool) -> Vec<u8> {
        let status = page.status;
        let headers = self.headers(page);
        let fields: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let mut out = web::h3_response_headers(status, &fields);
        if !head_only && !page.body.is_empty() {
            out.extend(proto::auth::encode_data_frame(&page.body));
        }
        out
    }
}

fn html(status: u16, body: &str) -> Page {
    Page {
        status,
        content_type: "text/html",
        body: body.as_bytes().to_vec(),
    }
}

/// Reads `path` under `dir`; `..`, absolute escapes and oversized files are refused.
fn read_file(dir: &Path, path: &str) -> Option<(Vec<u8>, &'static str)> {
    let relative = Path::new(path.trim_start_matches('/'));
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return None;
    }
    let mut file = dir.join(relative);
    if file.is_dir() {
        file = file.join("index.html");
    }
    let meta = std::fs::metadata(&file).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    let content_type = match file.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "txt" => "text/plain",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "webp" => "image/webp",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    };
    Some((std::fs::read(file).ok()?, content_type))
}

fn title_case(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut c = part.chars();
            c.next()
                .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// IMF-fixdate (RFC 9110 §5.6.7), e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn http_date(time: SystemTime) -> String {
    let secs = time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {day:02} {} {year} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[(days % 7) as usize],
        MONTHS[(month - 1) as usize],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Serves HTTP/1.1 on `io` starting with the bytes already read, until the visitor goes.
pub async fn serve_http1<S: AsyncRead + AsyncWrite + Unpin>(
    mut io: S,
    mut buf: Vec<u8>,
    site: &Site,
) {
    for _ in 0..MAX_REQUESTS {
        let (request, used) = loop {
            match web::parse_http1(&buf) {
                Ok(Some(parsed)) => break parsed,
                Ok(None) => {}
                Err(_) => {
                    let _ = io
                        .write_all(&site.http1(&html(400, NOT_FOUND), false, true))
                        .await;
                    let _ = io.shutdown().await;
                    return;
                }
            }
            let mut chunk = [0u8; 4096];
            match tokio::time::timeout(KEEP_ALIVE, io.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                _ => return,
            }
        };
        buf.drain(..used);
        let page = site.page(&request.method, &request.path);
        let response = site.http1(&page, request.method == "HEAD", request.close);
        if io.write_all(&response).await.is_err() || request.close {
            break;
        }
    }
    let _ = io.shutdown().await;
}

/// Answers one HTTP/3 request stream.
pub async fn respond_h3(mut send: quinn::SendStream, request: &WebRequest, site: &Site) {
    let page = site.page(&request.method, &request.path);
    let _ = send
        .write_all(&site.h3(&page, request.method == "HEAD"))
        .await;
    let _ = send.finish();
}

/// Serves an HTTP/3 visitor: the server control stream, the first request, then every new
/// request stream until the connection goes idle.
pub async fn serve_h3(conn: quinn::Connection, first: (quinn::SendStream, WebRequest), site: Site) {
    if let Ok(mut control) = conn.open_uni().await {
        let _ = control.write_all(&web::h3_server_control_stream()).await;
        // Kept open for the connection's life, as HTTP/3 requires.
        tokio::spawn(async move {
            let _ = control.stopped().await;
        });
    }
    respond_h3(first.0, &first.1, &site).await;
    while let Ok((send, mut recv)) = conn.accept_bi().await {
        let site = site.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match web::parse_h3(&buf) {
                    Ok(Some((request, _))) => return respond_h3(send, &request, &site).await,
                    Ok(None) => {}
                    Err(_) => return,
                }
                match recv.read(&mut chunk).await {
                    Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                    _ => return,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_imf_fixdate() {
        assert_eq!(
            http_date(UNIX_EPOCH + Duration::from_secs(784_111_777)),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            http_date(UNIX_EPOCH + Duration::from_secs(951_782_400)),
            "Tue, 29 Feb 2000 00:00:00 GMT"
        );
    }

    #[test]
    fn files_are_served_and_escapes_refused() {
        let dir = std::env::temp_dir().join(format!("partizan-site-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("css")).unwrap();
        std::fs::write(dir.join("index.html"), "<h1>home</h1>").unwrap();
        std::fs::write(dir.join("css/site.css"), "body{}").unwrap();
        let site = Site::new(Some(dir.clone()), 443);
        assert_eq!(site.page("GET", "/").body, b"<h1>home</h1>");
        assert_eq!(
            site.page("GET", "/css/site.css?v=2").content_type,
            "text/css"
        );
        for path in ["/../etc/passwd", "/css/../../etc/passwd", "/missing"] {
            assert_eq!(site.page("GET", path).status, 404, "{path}");
        }
        assert_eq!(site.page("POST", "/").status, 405);
        let default = Site::new(None, 443);
        assert_eq!(default.page("GET", "/").status, 200);
        assert_eq!(default.page("GET", "/api/v2/sync").status, 404);
    }
}
