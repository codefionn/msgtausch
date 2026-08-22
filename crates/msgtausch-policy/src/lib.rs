//! Runtime traffic classifiers.
//!
//! Config parsing deliberately stays in `config`.  This module turns the
//! declarative rules into small, allocation-free predicates used on the proxy
//! request path.

use std::{collections::HashMap, net::IpAddr, sync::Arc};

use anyhow::{Context, Result, bail};

use msgtausch_config::{CacheConfig, Classifier, Config, DomainOp as ConfigDomainOp, Forward};

pub mod domain_list;

use crate::domain_list::{DomainMatcher, RemoteDomainList};

/// Information available while deciding whether to allow or route traffic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub client_ip: Option<IpAddr>,
}

impl Target {
    pub fn new(host: impl Into<String>, port: u16, client_ip: Option<IpAddr>) -> Self {
        Self {
            host: host.into().trim_end_matches('.').to_ascii_lowercase(),
            port,
            client_ip,
        }
    }

    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A compiled classifier. References point to the same named predicates, so
/// composing rules does not copy a domain list for every forward rule.
#[derive(Clone, Debug)]
pub enum CompiledClassifier {
    True,
    False,
    And(Vec<CompiledClassifier>),
    Or(Vec<CompiledClassifier>),
    Not(Box<CompiledClassifier>),
    Domain { op: DomainOp, value: String },
    Port(u16),
    ClientIp(IpAddr),
    ClientNetwork(ipnet::IpNet),
    Domains(Arc<DomainMatcher>),
    RemoteDomains(Arc<RemoteDomainList>),
    Ref(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainOp {
    Equal,
    NotEqual,
    Contains,
    NotContains,
    /// Exact domain or a child domain.
    Is,
}

/// A stack-only chain of named references being evaluated. Classifiers are
/// validated when an engine is built, but `CompiledClassifier::matches` is
/// public and must still reject cycles in manually-built classifiers.
struct ReferenceTrail<'a> {
    id: &'a str,
    parent: Option<&'a Self>,
}

impl ReferenceTrail<'_> {
    fn contains(&self, id: &str) -> bool {
        self.id == id || self.parent.is_some_and(|parent| parent.contains(id))
    }
}

impl CompiledClassifier {
    pub fn matches(
        &self,
        target: &Target,
        named: &HashMap<String, CompiledClassifier>,
    ) -> Result<bool> {
        self.matches_inner(target, named, None)
    }

    fn matches_inner<'a>(
        &'a self,
        target: &Target,
        named: &'a HashMap<String, CompiledClassifier>,
        refs: Option<&'a ReferenceTrail<'a>>,
    ) -> Result<bool> {
        Ok(match self {
            Self::True => true,
            Self::False => false,
            Self::And(classifiers) => {
                for classifier in classifiers {
                    if !classifier.matches_inner(target, named, refs)? {
                        return Ok(false);
                    }
                }
                true
            }
            Self::Or(classifiers) => {
                for classifier in classifiers {
                    if classifier.matches_inner(target, named, refs)? {
                        return Ok(true);
                    }
                }
                false
            }
            Self::Not(classifier) => !classifier.matches_inner(target, named, refs)?,
            Self::Domain { op, value } => match op {
                DomainOp::Equal => target.host == *value,
                DomainOp::NotEqual => target.host != *value,
                DomainOp::Contains => target.host.contains(value),
                DomainOp::NotContains => !target.host.contains(value),
                DomainOp::Is => domain_or_subdomain(&target.host, value),
            },
            Self::Port(port) => target.port == *port,
            Self::ClientIp(ip) => target.client_ip == Some(*ip),
            Self::ClientNetwork(network) => {
                target.client_ip.is_some_and(|ip| network.contains(&ip))
            }
            Self::Domains(domains) => domains.matches(&target.host),
            Self::RemoteDomains(domains) => domains.matches(&target.host),
            Self::Ref(id) => {
                if refs.is_some_and(|refs| refs.contains(id)) {
                    bail!("cyclic classifier reference involving '{id}'");
                }
                let classifier = named
                    .get(id)
                    .with_context(|| format!("classifier reference '{id}' was not found"))?;
                let refs = ReferenceTrail { id, parent: refs };
                classifier.matches_inner(target, named, Some(&refs))?
            }
        })
    }
}

fn domain_or_subdomain(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Classifiers ready for use by the runtime. It owns domain file data and
/// preserves the order of configured forwards.
#[derive(Clone, Debug, Default)]
pub struct ClassifierEngine {
    named: HashMap<String, CompiledClassifier>,
    allowlist: Option<CompiledClassifier>,
    blocklist: Option<CompiledClassifier>,
    forwards: Vec<(CompiledClassifier, Forward)>,
}

impl ClassifierEngine {
    pub fn from_config(config: &Config) -> Result<Self> {
        let named = config
            .classifiers
            .iter()
            .map(|(name, classifier)| Ok((name.clone(), compile(classifier, &config.cache)?)))
            .collect::<Result<HashMap<_, _>>>()?;
        validate_references(&named)?;
        let allowlist = config
            .allowlist
            .as_ref()
            .map(|item| compile(item, &config.cache))
            .transpose()?;
        let blocklist = config
            .blocklist
            .as_ref()
            .map(|item| compile(item, &config.cache))
            .transpose()?;
        let forwards = config
            .forwards
            .iter()
            .map(|forward| {
                Ok((
                    compile(&forward.classifier, &config.cache)?,
                    forward.clone(),
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            named,
            allowlist,
            blocklist,
            forwards,
        })
    }

    /// Allowlist is an inclusive gate. Blocklist wins when both rules match.
    pub fn allows(&self, target: &Target) -> Result<bool> {
        let allowed = self
            .allowlist
            .as_ref()
            .map(|classifier| classifier.matches(target, &self.named))
            .transpose()?
            .unwrap_or(true);
        if !allowed {
            return Ok(false);
        }
        Ok(!self
            .blocklist
            .as_ref()
            .map(|classifier| classifier.matches(target, &self.named))
            .transpose()?
            .unwrap_or(false))
    }

    /// Return the first route whose classifier matches the target.
    pub fn select_forward(&self, target: &Target) -> Result<Option<&Forward>> {
        for (classifier, forward) in &self.forwards {
            if classifier.matches(target, &self.named)? {
                return Ok(Some(forward));
            }
        }
        Ok(None)
    }

    /// Compile a runtime-only classifier in this engine's named namespace.
    /// Runtime rules cannot declare a remote list inline, because downloading
    /// one here would create a separate list lifecycle. A reference to an
    /// already compiled named remote list remains valid.
    pub fn compile_runtime_classifier(
        &self,
        classifier: &Classifier,
    ) -> Result<CompiledClassifier> {
        let compiled = Self::compile_runtime_classifier_unvalidated(classifier)?;
        validate_classifier_references(&compiled, &self.named, &mut Vec::new())?;
        Ok(compiled)
    }

    /// Compile a runtime-only classifier without checking named references.
    /// This preserves the legacy interception constructors, which receive the
    /// named namespace later through `should_intercept`.
    pub fn compile_runtime_classifier_unvalidated(
        classifier: &Classifier,
    ) -> Result<CompiledClassifier> {
        if contains_remote_domains(classifier) {
            bail!("a runtime classifier with domains-url must use a named classifier reference")
        }
        compile(classifier, &CacheConfig::default())
    }

    /// Match a classifier previously compiled by `compile_runtime_classifier`.
    pub fn matches_compiled(
        &self,
        classifier: &CompiledClassifier,
        target: &Target,
    ) -> Result<bool> {
        classifier.matches(target, &self.named)
    }

    /// Evaluate a configuration classifier in the same named-classifier
    /// namespace as this engine. Kept as a convenience for callers which do
    /// not retain a compiled runtime rule.
    pub fn matches_config(&self, classifier: &Classifier, target: &Target) -> Result<bool> {
        let compiled = self.compile_runtime_classifier(classifier)?;
        self.matches_compiled(&compiled, target)
    }

    /// Refresh every remote list in this engine. Call this from a lifecycle
    /// task at the configured cache refresh interval. Matching remains purely
    /// synchronous while refresh downloads and swaps immutable matchers.
    pub fn refresh_remote_domains(&self) -> Result<()> {
        for classifier in self.named.values() {
            refresh_classifier(classifier)?;
        }
        if let Some(classifier) = &self.allowlist {
            refresh_classifier(classifier)?;
        }
        if let Some(classifier) = &self.blocklist {
            refresh_classifier(classifier)?;
        }
        for (classifier, _) in &self.forwards {
            refresh_classifier(classifier)?;
        }
        Ok(())
    }
}

fn contains_remote_domains(classifier: &Classifier) -> bool {
    match classifier {
        Classifier::DomainsUrl { .. } => true,
        Classifier::And(items) | Classifier::Or(items) => items.iter().any(contains_remote_domains),
        Classifier::Not(item) | Classifier::Record(item) => contains_remote_domains(item),
        _ => false,
    }
}

fn compile(classifier: &Classifier, cache: &CacheConfig) -> Result<CompiledClassifier> {
    Ok(match classifier {
        Classifier::True => CompiledClassifier::True,
        Classifier::False => CompiledClassifier::False,
        Classifier::And(items) => CompiledClassifier::And(
            items
                .iter()
                .map(|item| compile(item, cache))
                .collect::<Result<_>>()?,
        ),
        Classifier::Or(items) => CompiledClassifier::Or(
            items
                .iter()
                .map(|item| compile(item, cache))
                .collect::<Result<_>>()?,
        ),
        Classifier::Not(item) => CompiledClassifier::Not(Box::new(compile(item, cache)?)),
        Classifier::Domain { op, domain } => CompiledClassifier::Domain {
            op: match op {
                ConfigDomainOp::Equal => DomainOp::Equal,
                ConfigDomainOp::NotEqual => DomainOp::NotEqual,
                ConfigDomainOp::Contains => DomainOp::Contains,
                ConfigDomainOp::NotContains => DomainOp::NotContains,
                ConfigDomainOp::Is => DomainOp::Is,
            },
            value: domain.trim_end_matches('.').to_ascii_lowercase(),
        },
        Classifier::Ref(name) => CompiledClassifier::Ref(name.clone()),
        Classifier::Ip(value) => CompiledClassifier::ClientIp(
            value
                .parse()
                .with_context(|| format!("invalid classifier IP '{value}'"))?,
        ),
        Classifier::Network(value) => CompiledClassifier::ClientNetwork(
            value
                .parse()
                .with_context(|| format!("invalid classifier network '{value}'"))?,
        ),
        Classifier::Port(port) => CompiledClassifier::Port(*port),
        Classifier::DomainsFile(path) => CompiledClassifier::Domains(Arc::new(
            DomainMatcher::from_local_tokens(load_domains_file(path)?),
        )),
        Classifier::DomainsUrl {
            url,
            mirrors,
            format,
            timeout_seconds,
        } => CompiledClassifier::RemoteDomains(Arc::new(RemoteDomainList::new(
            url.clone(),
            mirrors.clone(),
            *format,
            *timeout_seconds,
            cache,
        )?)),
        Classifier::Record(item) => compile(item, cache)?,
    })
}

fn refresh_classifier(classifier: &CompiledClassifier) -> Result<()> {
    match classifier {
        CompiledClassifier::And(items) | CompiledClassifier::Or(items) => {
            for item in items {
                refresh_classifier(item)?;
            }
        }
        CompiledClassifier::Not(item) => refresh_classifier(item)?,
        CompiledClassifier::RemoteDomains(list) => list.refresh()?,
        _ => {}
    }
    Ok(())
}

fn validate_references(named: &HashMap<String, CompiledClassifier>) -> Result<()> {
    for classifier in named.values() {
        validate_classifier_references(classifier, named, &mut Vec::new())?;
    }
    Ok(())
}

fn validate_classifier_references(
    classifier: &CompiledClassifier,
    named: &HashMap<String, CompiledClassifier>,
    refs: &mut Vec<String>,
) -> Result<()> {
    match classifier {
        CompiledClassifier::And(items) | CompiledClassifier::Or(items) => {
            for item in items {
                validate_classifier_references(item, named, refs)?;
            }
        }
        CompiledClassifier::Not(item) => validate_classifier_references(item, named, refs)?,
        CompiledClassifier::Ref(name) => {
            if refs.contains(name) {
                bail!("cyclic classifier reference involving '{name}'");
            }
            let item = named
                .get(name)
                .with_context(|| format!("classifier reference '{name}' was not found"))?;
            refs.push(name.clone());
            validate_classifier_references(item, named, refs)?;
            refs.pop();
        }
        _ => {}
    }
    Ok(())
}

/// Read a legacy domains file. Blank lines and `#` or `;` comments are ignored.
pub fn load_domains_file(path: &std::path::Path) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading domains file {}", path.display()))?;
    let domains = content
        .lines()
        .filter_map(|line| line.split(['#', ';']).next())
        .flat_map(str::split_whitespace)
        .map(|domain| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
        .collect();
    Ok(domains)
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use msgtausch_config::{
        CacheConfig, Classifier, Config, DomainOp as ConfigDomainOp, DomainsUrlFormat, Forward,
        ForwardKind,
    };

    use super::{ClassifierEngine, CompiledClassifier, DomainOp, Target};

    #[test]
    fn is_matches_subdomains_but_equal_does_not() {
        let target = Target::new("api.example.com", 443, None);
        let named = HashMap::new();
        assert!(
            CompiledClassifier::Domain {
                op: DomainOp::Is,
                value: "example.com".into(),
            }
            .matches(&target, &named)
            .unwrap()
        );
        assert!(
            !CompiledClassifier::Domain {
                op: DomainOp::Equal,
                value: "example.com".into(),
            }
            .matches(&target, &named)
            .unwrap()
        );
    }

    #[test]
    fn named_references_and_client_networks_work() {
        let mut named = HashMap::new();
        named.insert(
            "corp".into(),
            CompiledClassifier::ClientNetwork("10.0.0.0/8".parse().unwrap()),
        );
        let target = Target::new("example.com", 80, Some("10.3.2.1".parse().unwrap()));
        assert!(
            CompiledClassifier::Ref("corp".into())
                .matches(&target, &named)
                .unwrap()
        );
        assert_eq!(
            target.client_ip.unwrap(),
            std::net::IpAddr::from_str("10.3.2.1").unwrap()
        );
    }

    #[test]
    fn cyclic_reference_is_an_error() {
        let mut named = HashMap::new();
        named.insert("a".into(), CompiledClassifier::Ref("b".into()));
        named.insert("b".into(), CompiledClassifier::Ref("a".into()));
        assert!(
            CompiledClassifier::Ref("a".into())
                .matches(&Target::new("example.com", 80, None), &named)
                .is_err()
        );
    }

    #[test]
    fn access_control_precedes_first_matching_route() {
        let config = Config {
            classifiers: [(
                "corp".into(),
                Classifier::Domain {
                    op: ConfigDomainOp::Is,
                    domain: "corp.test".into(),
                },
            )]
            .into(),
            allowlist: Some(Classifier::Ref("corp".into())),
            blocklist: Some(Classifier::Domain {
                op: ConfigDomainOp::Is,
                domain: "blocked.corp.test".into(),
            }),
            forwards: vec![
                Forward {
                    kind: ForwardKind::Socks5 {
                        address: "127.0.0.1:1080".into(),
                        username: None,
                        password: None,
                    },
                    classifier: Classifier::True,
                    force_ipv4: false,
                    log: false,
                },
                Forward {
                    kind: ForwardKind::Direct,
                    classifier: Classifier::True,
                    force_ipv4: false,
                    log: false,
                },
            ],
            ..Config::default()
        };
        let engine = ClassifierEngine::from_config(&config).unwrap();
        let accepted = Target::new("api.corp.test", 443, None);
        assert!(engine.allows(&accepted).unwrap());
        assert!(matches!(
            engine.select_forward(&accepted).unwrap().unwrap().kind,
            ForwardKind::Socks5 { .. }
        ));
        assert!(
            !engine
                .allows(&Target::new("blocked.corp.test", 443, None))
                .unwrap()
        );
        assert!(
            !engine
                .allows(&Target::new("public.test", 443, None))
                .unwrap()
        );
    }

    #[test]
    fn local_domain_files_keep_legacy_non_dns_tokens() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            file.path(),
            "LOCALHOST. # local listener\n127.0.0.1.\nSINGLE-LABEL.\nodd/token.\n",
        )
        .unwrap();
        let config = Config {
            allowlist: Some(Classifier::DomainsFile(file.path().to_owned())),
            ..Config::default()
        };
        let engine = ClassifierEngine::from_config(&config).unwrap();
        for host in [
            "localhost",
            "api.localhost",
            "127.0.0.1",
            "single-label",
            "odd/token",
        ] {
            assert!(
                engine.allows(&Target::new(host, 443, None)).unwrap(),
                "{host}"
            );
        }
    }

    #[test]
    fn runtime_classifier_accepts_named_remote_lists_and_rejects_inline_ones() {
        let config = Config {
            classifiers: [(
                "remote".into(),
                Classifier::DomainsUrl {
                    url: "http://127.0.0.1:9/never-reached".into(),
                    mirrors: vec![],
                    format: DomainsUrlFormat::Plain,
                    timeout_seconds: 1,
                },
            )]
            .into(),
            cache: CacheConfig {
                max_retries: 0,
                retry_delay_seconds: 0,
                ..CacheConfig::default()
            },
            ..Config::default()
        };
        let engine = ClassifierEngine::from_config(&config).unwrap();
        assert!(
            engine
                .compile_runtime_classifier(&Classifier::Ref("remote".into()))
                .is_ok()
        );
        assert!(
            engine
                .compile_runtime_classifier(&Classifier::DomainsUrl {
                    url: "http://127.0.0.1:9/never-reached".into(),
                    mirrors: vec![],
                    format: DomainsUrlFormat::Plain,
                    timeout_seconds: 1,
                })
                .is_err()
        );
        assert!(
            engine
                .compile_runtime_classifier(&Classifier::Ref("missing".into()))
                .is_err()
        );
    }
}
