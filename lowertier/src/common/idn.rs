use idna::domain_to_ascii;
use percent_encoding::percent_decode_str;

pub fn convert_idn_to_ascii(mut url: url::Url) -> anyhow::Result<url::Url> {
    if url.is_special() {
        return Ok(url);
    }
    if let Some(domain) = url.domain() {
        let domain = percent_decode_str(domain).decode_utf8()?;
        let domain = domain_to_ascii(&domain)?;
        url.set_host(Some(&domain))?;
    }
    Ok(url)
}
