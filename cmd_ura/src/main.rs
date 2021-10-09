use anyhow::anyhow;
use anyhow::Result;
use structopt::StructOpt;
use std::path::PathBuf;
use http::Uri;
use std::fs;
use std::sync::Arc;
use std::io::Write;

mod attestation;
use attestation::report::AttestationReport;

#[derive(Debug, StructOpt)]
#[structopt(name = "cmd_ura", about = "Universe01 Remote Attestation command line tool.")]
struct Opt {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
    /// Display the attestation report of remote Teaclave services
    #[structopt(name = "attest")]
    Attest(AttestOpt),

    // TODO: Add new subcommand
}

#[derive(Debug, StructOpt)]
struct AttestOpt {
    /// Address of the rpc service running in an enclave
    #[structopt(short, long)]
    address: String,

    /// CA cert of attestation service for verifying the attestation report
    #[structopt(short = "c", long, default_value = "/home/chenge/reconstruction/universe01_tee/keys/dcap_root_ca_cert.pem")]
    as_ca_cert: PathBuf,
}

struct TeeServerCertVerifier {
    pub root_ca: Vec<u8>,
}

impl TeeServerCertVerifier {
    pub fn new(root_ca: &[u8]) -> Self {
        Self {
            root_ca: root_ca.to_vec(),
        }
    }

    fn display_attestation_report(&self, cert_der: &[u8]) -> bool {
        match AttestationReport::from_cert(&cert_der, &self.root_ca) {
            Ok(report) => println!("{}", report),
            Err(e) => println!("{:?}", e),
        }
        true
    }
}

impl rustls::ServerCertVerifier for TeeServerCertVerifier {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef,
        _ocsp: &[u8],
    ) -> std::result::Result<rustls::ServerCertVerified, rustls::TLSError> {
        // This call automatically verifies certificate signature
        if certs.len() != 1 {
            return Err(rustls::TLSError::NoCertificatesPresented);
        }
        if self.display_attestation_report(&certs[0].0) {
            Ok(rustls::ServerCertVerified::assertion())
        } else {
            Err(rustls::TLSError::WebPKIError(
                webpki::Error::ExtensionValueInvalid,
            ))
        }
    }
}

fn attest(opt: AttestOpt) -> Result<()> {
    let uri = opt.address.parse::<Uri>()?;
    let hostname = uri.host().ok_or_else(|| anyhow!("Invalid hostname."))?;
    let mut stream = std::net::TcpStream::connect(opt.address)?;
    let hostname = webpki::DNSNameRef::try_from_ascii_str(hostname)?;
    let content = fs::read(opt.as_ca_cert)?;
    let pem = pem::parse(content)?;
    let verifier = Arc::new(TeeServerCertVerifier::new(&pem.contents));
    let mut config = rustls::ClientConfig::new();
    config.dangerous().set_certificate_verifier(verifier);
    config.versions.clear();
    config.enable_sni = false;
    config.versions.push(rustls::ProtocolVersion::TLSv1_2);
    let rc_config = Arc::new(config);

    let mut session = rustls::ClientSession::new(&rc_config, hostname);
    let mut tls_stream = rustls::Stream::new(&mut session, &mut stream);
    tls_stream.write_all(&[0]).unwrap();

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Opt::from_args();
    match args.command {
        Command::Attest(opt) => attest(opt)?,
    };

    Ok(())
}
