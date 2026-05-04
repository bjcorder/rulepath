use rulepath_ir::{
    Confidence, EvidenceFact, EvidenceKind, Framework, Language, RouteFact, SourceFact, SourceKind,
    SourceSpan,
};
use rulepath_parsers::ParsedFile;
use rulepath_workspace::SourceFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameworkDescriptor {
    pub id: Framework,
    pub name: &'static str,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameworkFacts {
    pub routes: Vec<RouteFact>,
    pub sources: Vec<SourceFact>,
    pub evidence: Vec<EvidenceFact>,
}

pub trait FrameworkAdapter {
    fn descriptor(&self) -> FrameworkDescriptor;
    fn extract(
        &self,
        file: &SourceFile,
        parsed: &ParsedFile,
        route_offset: usize,
    ) -> FrameworkFacts;
}

#[derive(Debug, Clone, Copy)]
struct BuiltInFrameworkAdapter {
    descriptor: FrameworkDescriptor,
}

impl FrameworkAdapter for BuiltInFrameworkAdapter {
    fn descriptor(&self) -> FrameworkDescriptor {
        self.descriptor
    }

    fn extract(
        &self,
        file: &SourceFile,
        parsed: &ParsedFile,
        route_offset: usize,
    ) -> FrameworkFacts {
        match self.descriptor.id {
            Framework::Express => extract_express(file, parsed, route_offset),
            Framework::FastApi => extract_fastapi(file, parsed, route_offset),
            Framework::DjangoRestFramework => extract_django_rest_framework(file, route_offset),
            Framework::NextJs => extract_nextjs(file, parsed, route_offset),
            Framework::Django | Framework::Unknown => FrameworkFacts::default(),
        }
    }
}

static BUILT_IN_FRAMEWORK_ADAPTERS: &[BuiltInFrameworkAdapter] = &[
    BuiltInFrameworkAdapter {
        descriptor: FrameworkDescriptor {
            id: Framework::Express,
            name: "express",
        },
    },
    BuiltInFrameworkAdapter {
        descriptor: FrameworkDescriptor {
            id: Framework::FastApi,
            name: "fastapi",
        },
    },
    BuiltInFrameworkAdapter {
        descriptor: FrameworkDescriptor {
            id: Framework::Django,
            name: "django",
        },
    },
    BuiltInFrameworkAdapter {
        descriptor: FrameworkDescriptor {
            id: Framework::DjangoRestFramework,
            name: "django_rest_framework",
        },
    },
    BuiltInFrameworkAdapter {
        descriptor: FrameworkDescriptor {
            id: Framework::NextJs,
            name: "nextjs",
        },
    },
];

#[must_use]
pub fn built_in_frameworks() -> Vec<&'static dyn FrameworkAdapter> {
    BUILT_IN_FRAMEWORK_ADAPTERS
        .iter()
        .map(|adapter| adapter as &dyn FrameworkAdapter)
        .collect()
}

#[must_use]
pub fn built_in_framework_descriptors() -> Vec<FrameworkDescriptor> {
    BUILT_IN_FRAMEWORK_ADAPTERS
        .iter()
        .map(|adapter| adapter.descriptor())
        .collect()
}

#[must_use]
pub fn extract_auth_evidence(file: &SourceFile, parsed: &ParsedFile) -> Vec<EvidenceFact> {
    let evidence_specs = [
        (
            "requireAuth",
            EvidenceKind::Authentication,
            "authentication:requireAuth",
        ),
        (
            "withAuth",
            EvidenceKind::Authentication,
            "authentication:withAuth",
        ),
        ("auth", EvidenceKind::Authentication, "authentication:auth"),
        (
            "getServerSession",
            EvidenceKind::Authentication,
            "authentication:getServerSession",
        ),
        (
            "get_current_user",
            EvidenceKind::Authentication,
            "authentication:get_current_user",
        ),
        (
            "IsAuthenticated",
            EvidenceKind::Authentication,
            "authentication:IsAuthenticated",
        ),
        (
            "requirePermission",
            EvidenceKind::Authorization,
            "authorization:requirePermission",
        ),
        (
            "require_permission",
            EvidenceKind::Authorization,
            "authorization:require_permission",
        ),
        (
            "permission_required",
            EvidenceKind::Authorization,
            "authorization:permission_required",
        ),
        (
            "has_perm",
            EvidenceKind::Authorization,
            "authorization:has_perm",
        ),
        (
            "check_object_permissions",
            EvidenceKind::ObjectScope,
            "object_scope:check_object_permissions",
        ),
    ];

    let mut evidence = Vec::new();
    for call in &parsed.calls {
        let helper = call
            .callee
            .rsplit('.')
            .next()
            .unwrap_or(call.callee.as_str());
        if let Some((_, kind, label)) = evidence_specs
            .iter()
            .find(|(needle, _, _)| helper == *needle || call.callee == *needle)
        {
            evidence.push(EvidenceFact {
                id: format!(
                    "evidence:{}:{}:{helper}",
                    file.relative_path, call.span.start.line
                ),
                kind: *kind,
                label: (*label).to_owned(),
                expression: call.callee.clone(),
                confidence: Confidence::High,
                route_id: None,
                sink_id: None,
                span: call.span.clone(),
            });
        }
    }
    evidence
}

fn extract_express(file: &SourceFile, parsed: &ParsedFile, route_offset: usize) -> FrameworkFacts {
    if file.language != Language::TypeScript {
        return FrameworkFacts::default();
    }
    let mut facts = FrameworkFacts::default();
    for call in &parsed.calls {
        let Some(method) = express_method(call.callee.as_str()) else {
            continue;
        };
        let Some(path) = call.arguments.first().and_then(|arg| literal_argument(arg)) else {
            continue;
        };
        let middleware = express_middleware(&call.arguments);
        let handler = express_handler(&call.arguments);
        push_route(
            file,
            &mut facts,
            Framework::Express,
            method.to_owned(),
            path,
            handler,
            middleware,
            call.span.clone(),
            route_offset,
        );
    }
    facts
}

fn extract_fastapi(file: &SourceFile, parsed: &ParsedFile, route_offset: usize) -> FrameworkFacts {
    if file.language != Language::Python {
        return FrameworkFacts::default();
    }
    let mut facts = FrameworkFacts::default();
    for call in &parsed.calls {
        let Some(method) = fastapi_method(call.callee.as_str()) else {
            continue;
        };
        let Some(path) = call.arguments.first().and_then(|arg| literal_argument(arg)) else {
            continue;
        };
        let handler = parsed
            .symbols
            .iter()
            .find(|symbol| symbol.span.start.line > call.span.start.line)
            .map(|symbol| symbol.name.clone())
            .unwrap_or_else(|| "fastapi_handler".to_owned());
        let middleware = fastapi_dependencies(file, parsed, call.span.start.line, handler.as_str());
        push_route(
            file,
            &mut facts,
            Framework::FastApi,
            method.to_owned(),
            path,
            handler,
            middleware,
            call.span.clone(),
            route_offset,
        );
    }
    facts
}

fn extract_nextjs(file: &SourceFile, parsed: &ParsedFile, route_offset: usize) -> FrameworkFacts {
    if file.language != Language::TypeScript
        || (!file.relative_path.contains("app/api/") && !file.relative_path.contains("pages/api/"))
    {
        return FrameworkFacts::default();
    }
    let mut facts = FrameworkFacts::default();
    for symbol in &parsed.symbols {
        if matches!(
            symbol.name.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
        ) {
            push_route(
                file,
                &mut facts,
                Framework::NextJs,
                symbol.name.clone(),
                path_from_nextjs_file(file.relative_path.as_str()),
                symbol.name.clone(),
                Vec::new(),
                symbol.span.clone(),
                route_offset,
            );
        }
    }
    facts
}

fn extract_django_rest_framework(file: &SourceFile, route_offset: usize) -> FrameworkFacts {
    if file.language != Language::Python {
        return FrameworkFacts::default();
    }
    let mut facts = FrameworkFacts::default();
    let lines = file.text.lines().collect::<Vec<_>>();
    for (line_index, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("class ")
            && (trimmed.contains("ModelViewSet") || trimmed.contains("APIView"))
        {
            push_route(
                file,
                &mut facts,
                Framework::DjangoRestFramework,
                "GET".to_owned(),
                inferred_django_path(file),
                class_name_from_line(line).unwrap_or_else(|| "drf_view".to_owned()),
                django_permission_classes(&lines, line_index),
                SourceSpan::single_line(file.relative_path.as_str(), line_index + 1),
                route_offset,
            );
        }
    }
    facts
}

fn push_route(
    file: &SourceFile,
    facts: &mut FrameworkFacts,
    framework: Framework,
    method: String,
    path: String,
    handler: String,
    middleware: Vec<String>,
    span: SourceSpan,
    route_offset: usize,
) {
    let id = format!(
        "route:{framework:?}:{method}:{path}:{}",
        route_offset + facts.routes.len()
    );
    let body_source = format!("source:{}:body", file.relative_path);
    let param_source = format!("source:{}:route_param", file.relative_path);
    facts.sources.push(SourceFact {
        id: body_source.clone(),
        kind: SourceKind::Body,
        name: "body".to_owned(),
        expression: body_expression(framework),
        controlled_by_request: true,
        span: span.clone(),
    });
    facts.sources.push(SourceFact {
        id: param_source.clone(),
        kind: SourceKind::RouteParam,
        name: route_param_name(framework, path.as_str()).unwrap_or_else(|| "id".to_owned()),
        expression: param_expression(framework),
        controlled_by_request: true,
        span: span.clone(),
    });
    facts.routes.push(RouteFact {
        id,
        framework,
        language: file.language,
        method,
        path,
        handler,
        span,
        middleware,
        sources: vec![param_source, body_source],
    });
}

fn express_middleware(arguments: &[String]) -> Vec<String> {
    if arguments.len() <= 2 {
        return Vec::new();
    }
    arguments[1..arguments.len() - 1]
        .iter()
        .filter_map(|argument| middleware_name(argument))
        .collect()
}

fn express_handler(arguments: &[String]) -> String {
    arguments
        .last()
        .and_then(|argument| {
            let trimmed = argument.trim();
            if trimmed.contains("=>")
                || trimmed.starts_with("function")
                || trimmed.starts_with("async (")
            {
                Some("inline_handler".to_owned())
            } else {
                middleware_name(trimmed)
            }
        })
        .unwrap_or_else(|| "inline_handler".to_owned())
}

fn fastapi_dependencies(
    file: &SourceFile,
    parsed: &ParsedFile,
    decorator_line: usize,
    handler: &str,
) -> Vec<String> {
    let handler_end = parsed
        .symbols
        .iter()
        .filter(|symbol| symbol.span.start.line > decorator_line)
        .nth(1)
        .map_or(decorator_line + 20, |symbol| {
            symbol.span.start.line.saturating_sub(1)
        });
    let mut dependencies = parsed
        .calls
        .iter()
        .filter(|call| call.callee == "Depends")
        .filter(|call| {
            call.span.start.line >= decorator_line && call.span.start.line <= handler_end
        })
        .filter_map(|call| call.arguments.first())
        .filter_map(|argument| middleware_name(argument))
        .collect::<Vec<_>>();
    if dependencies.is_empty() {
        if let Some(signature) = function_signature_line(file, handler) {
            dependencies.extend(depends_names_from_text(signature));
        }
    }
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

fn function_signature_line<'a>(file: &'a SourceFile, handler: &str) -> Option<&'a str> {
    file.text.lines().find(|line| {
        line.trim_start().starts_with(&format!("def {handler}("))
            || line
                .trim_start()
                .starts_with(&format!("async def {handler}("))
    })
}

fn depends_names_from_text(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(index) = rest.find("Depends(") {
        rest = &rest[index + "Depends(".len()..];
        if let Some(name) = middleware_name(rest) {
            names.push(name);
        }
    }
    names
}

fn middleware_name(argument: &str) -> Option<String> {
    let trimmed = argument
        .trim()
        .trim_start_matches("Depends(")
        .trim_end_matches(')')
        .trim();
    let name = trimmed
        .split('(')
        .next()
        .unwrap_or(trimmed)
        .split(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '_' || character == '.')
        })
        .next()
        .unwrap_or_default()
        .trim();
    (!name.is_empty()).then(|| name.rsplit('.').next().unwrap_or(name).to_owned())
}

fn route_param_name(framework: Framework, path: &str) -> Option<String> {
    match framework {
        Framework::FastApi | Framework::Django | Framework::DjangoRestFramework => path
            .split('{')
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .map(ToOwned::to_owned),
        _ => path
            .split(':')
            .nth(1)
            .map(|rest| {
                rest.chars()
                    .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                    .collect::<String>()
            })
            .filter(|name| !name.is_empty()),
    }
}

fn django_permission_classes(lines: &[&str], class_line_index: usize) -> Vec<String> {
    let mut classes = Vec::new();
    for line in lines.iter().skip(class_line_index + 1) {
        let trimmed = line.trim();
        if trimmed.starts_with("class ") {
            break;
        }
        if !trimmed.starts_with("permission_classes") {
            continue;
        }
        let Some(open) = trimmed.find('[') else {
            continue;
        };
        let Some(close) = trimmed[open + 1..].find(']') else {
            continue;
        };
        classes.extend(
            trimmed[open + 1..open + 1 + close]
                .split(',')
                .filter_map(|item| {
                    let name = item.trim();
                    (!name.is_empty()).then(|| name.to_owned())
                }),
        );
    }
    classes
}

fn express_method(callee: &str) -> Option<&'static str> {
    for method in ["get", "post", "put", "patch", "delete"] {
        if callee == format!("router.{method}") || callee == format!("app.{method}") {
            return Some(match method {
                "get" => "GET",
                "post" => "POST",
                "put" => "PUT",
                "patch" => "PATCH",
                "delete" => "DELETE",
                _ => unreachable!(),
            });
        }
    }
    None
}

fn fastapi_method(callee: &str) -> Option<&'static str> {
    for method in ["get", "post", "put", "patch", "delete"] {
        if callee == format!("router.{method}") || callee == format!("app.{method}") {
            return Some(match method {
                "get" => "GET",
                "post" => "POST",
                "put" => "PUT",
                "patch" => "PATCH",
                "delete" => "DELETE",
                _ => unreachable!(),
            });
        }
    }
    None
}

fn literal_argument(argument: &str) -> Option<String> {
    let trimmed = argument.trim();
    let quote = trimmed.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let rest = &trimmed[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_owned())
}

fn body_expression(framework: Framework) -> String {
    match framework {
        Framework::FastApi | Framework::Django | Framework::DjangoRestFramework => {
            "body".to_owned()
        }
        Framework::NextJs => "request.json()".to_owned(),
        _ => "req.body".to_owned(),
    }
}

fn param_expression(framework: Framework) -> String {
    match framework {
        Framework::FastApi | Framework::Django | Framework::DjangoRestFramework => {
            "path parameter".to_owned()
        }
        Framework::NextJs => "params".to_owned(),
        _ => "req.params".to_owned(),
    }
}

fn path_from_nextjs_file(relative_path: &str) -> String {
    let mut path = relative_path
        .replace("app/api", "")
        .replace("pages/api", "")
        .replace("/route.ts", "")
        .replace("/route.js", "")
        .replace(".ts", "")
        .replace(".js", "");
    path = path.replace('[', ":").replace(']', "");
    if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('/') {
        path
    } else {
        format!("/{path}")
    }
}

fn inferred_django_path(file: &SourceFile) -> String {
    format!("/{}", file.relative_path.replace(".py", ""))
}

fn class_name_from_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed.strip_prefix("class ")?;
    Some(
        rest.chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulepath_parsers::{CallFact, ParsedFile, SymbolFact, SymbolKind};

    #[test]
    fn adapters_are_registered_deterministically() {
        let descriptors = built_in_framework_descriptors();
        let names = descriptors
            .iter()
            .map(|descriptor| descriptor.name)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "express",
                "fastapi",
                "django",
                "django_rest_framework",
                "nextjs"
            ]
        );
    }

    #[test]
    fn express_extraction_uses_parsed_calls() {
        let file = SourceFile {
            path: "src/routes/invoices.ts".into(),
            relative_path: "src/routes/invoices.ts".to_owned(),
            language: Language::TypeScript,
            text: String::new(),
        };
        let parsed = ParsedFile {
            language: Language::TypeScript,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![CallFact {
                callee: "router.patch".to_owned(),
                arguments: vec!["\"/invoices/:id\"".to_owned()],
                span: SourceSpan::single_line("src/routes/invoices.ts", 3),
            }],
            suppressions: Vec::new(),
        };

        let facts = extract_express(&file, &parsed, 0);
        assert_eq!(facts.routes[0].method, "PATCH");
        assert_eq!(facts.routes[0].path, "/invoices/:id");
    }

    #[test]
    fn express_extraction_keeps_multiline_middleware_and_path_param() {
        let file = SourceFile {
            path: "src/routes/invoices.ts".into(),
            relative_path: "src/routes/invoices.ts".to_owned(),
            language: Language::TypeScript,
            text: String::new(),
        };
        let parsed = ParsedFile {
            language: Language::TypeScript,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![CallFact {
                callee: "router.patch".to_owned(),
                arguments: vec![
                    "\"/clients/:clientId/invoices/:invoiceId\"".to_owned(),
                    "requireAuth".to_owned(),
                    "requirePermission(\"invoice:update\")".to_owned(),
                    "async (req, res) => {\n await updateInvoice(req.params.invoiceId, req.body)\n}"
                        .to_owned(),
                ],
                span: SourceSpan::single_line("src/routes/invoices.ts", 10),
            }],
            suppressions: Vec::new(),
        };

        let facts = extract_express(&file, &parsed, 0);
        assert_eq!(
            facts.routes[0].middleware,
            vec!["requireAuth", "requirePermission"]
        );
        assert_eq!(facts.routes[0].handler, "inline_handler");
        let route_param = facts
            .sources
            .iter()
            .find(|source| source.id.ends_with(":route_param"))
            .expect("route param source should exist");
        assert_eq!(route_param.name, "clientId");
    }

    #[test]
    fn fastapi_extraction_uses_decorator_call_and_next_symbol() {
        let file = SourceFile {
            path: "app/routes.py".into(),
            relative_path: "app/routes.py".to_owned(),
            language: Language::Python,
            text: String::new(),
        };
        let parsed = ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: vec![SymbolFact {
                name: "update_invoice".to_owned(),
                kind: SymbolKind::Function,
                span: SourceSpan::single_line("app/routes.py", 4),
            }],
            calls: vec![CallFact {
                callee: "router.patch".to_owned(),
                arguments: vec!["\"/invoices/{invoice_id}\"".to_owned()],
                span: SourceSpan::single_line("app/routes.py", 3),
            }],
            suppressions: Vec::new(),
        };

        let facts = extract_fastapi(&file, &parsed, 0);
        assert_eq!(facts.routes[0].handler, "update_invoice");
    }

    #[test]
    fn fastapi_extraction_keeps_dependencies_and_path_param() {
        let file = SourceFile {
            path: "app/routes.py".into(),
            relative_path: "app/routes.py".to_owned(),
            language: Language::Python,
            text: "@router.patch(\"/invoices/{invoice_id}\", dependencies=[Depends(require_permission(\"invoice:update\"))])\ndef update_invoice(invoice_id: str, body: dict, current_user=Depends(get_current_user)):\n    pass\n".to_owned(),
        };
        let parsed = ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: vec![SymbolFact {
                name: "update_invoice".to_owned(),
                kind: SymbolKind::Function,
                span: SourceSpan::single_line("app/routes.py", 2),
            }],
            calls: vec![
                CallFact {
                    callee: "router.patch".to_owned(),
                    arguments: vec![
                        "\"/invoices/{invoice_id}\"".to_owned(),
                        "dependencies=[Depends(require_permission(\"invoice:update\"))]".to_owned(),
                    ],
                    span: SourceSpan::single_line("app/routes.py", 1),
                },
                CallFact {
                    callee: "Depends".to_owned(),
                    arguments: vec!["require_permission(\"invoice:update\")".to_owned()],
                    span: SourceSpan::single_line("app/routes.py", 1),
                },
                CallFact {
                    callee: "Depends".to_owned(),
                    arguments: vec!["get_current_user".to_owned()],
                    span: SourceSpan::single_line("app/routes.py", 2),
                },
            ],
            suppressions: Vec::new(),
        };

        let facts = extract_fastapi(&file, &parsed, 0);
        assert_eq!(
            facts.routes[0].middleware,
            vec!["get_current_user", "require_permission"]
        );
        let route_param = facts
            .sources
            .iter()
            .find(|source| source.id.ends_with(":route_param"))
            .expect("route param source should exist");
        assert_eq!(route_param.name, "invoice_id");
    }

    #[test]
    fn drf_extraction_uses_class_span_and_permission_classes() {
        let file = SourceFile {
            path: "app/views.py".into(),
            relative_path: "app/views.py".to_owned(),
            language: Language::Python,
            text: "from rest_framework.viewsets import ModelViewSet\n\nclass InvoiceViewSet(ModelViewSet):\n    permission_classes = [IsAuthenticated, InvoicePermission]\n"
                .to_owned(),
        };

        let facts = extract_django_rest_framework(&file, 0);
        assert_eq!(facts.routes[0].handler, "InvoiceViewSet");
        assert_eq!(facts.routes[0].span.start.line, 3);
        assert_eq!(
            facts.routes[0].middleware,
            vec!["IsAuthenticated", "InvoicePermission"]
        );
    }
}
