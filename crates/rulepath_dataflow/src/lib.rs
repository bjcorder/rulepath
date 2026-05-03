use rulepath_config::ResolvedConfig;
use rulepath_ir::{
    CallFrame, CallPath, Confidence, OperationFact, ProjectIr, RouteFact, SourceSpan,
};
use rulepath_parsers::{LanguageAdapter, ParsedFile, SymbolKind};
use rulepath_workspace::WorkspaceIndex;

pub struct ScanContext<'a> {
    pub index: &'a WorkspaceIndex,
    pub parsed_files: Vec<ParsedFile>,
    pub ir: ProjectIr,
}

pub fn build_project_ir(index: &WorkspaceIndex, config: &ResolvedConfig) -> ProjectIr {
    let mut context = ScanContext {
        index,
        parsed_files: parse_workspace(index),
        ir: ProjectIr::default(),
    };

    collect_framework_and_auth_facts(&mut context, config);
    collect_operation_facts(&mut context, config);

    let trace_index = build_trace_index(context.index, &context.parsed_files, &context.ir);
    attach_route_evidence(&mut context.ir);
    attach_call_paths(&mut context.ir, &trace_index);
    rewrite_operation_sources_to_route_sources(&mut context.ir);
    sort_project_ir(&mut context.ir);
    context.ir
}

fn parse_workspace(index: &WorkspaceIndex) -> Vec<ParsedFile> {
    let adapters = built_in_language_adapters();
    index
        .files
        .iter()
        .filter_map(|file| {
            adapters
                .iter()
                .find(|adapter| adapter.language_id() == file.language)
                .map(|adapter| adapter.parse_file(file))
        })
        .collect()
}

fn built_in_language_adapters() -> Vec<Box<dyn LanguageAdapter>> {
    vec![
        Box::<rulepath_lang_typescript::TypeScriptAdapter>::default(),
        Box::<rulepath_lang_python::PythonAdapter>::default(),
    ]
}

fn collect_framework_and_auth_facts(context: &mut ScanContext<'_>, config: &ResolvedConfig) {
    for file in &context.index.files {
        let Some(parsed) = parsed_for_file(&context.parsed_files, &file.relative_path) else {
            continue;
        };
        for adapter in rulepath_frameworks::built_in_frameworks() {
            let facts = adapter.extract(file, parsed, context.ir.routes.len());
            context.ir.routes.extend(facts.routes);
            context.ir.sources.extend(facts.sources);
            context.ir.evidence.extend(facts.evidence);
        }
        context
            .ir
            .evidence
            .extend(rulepath_auth::normalize_file_evidence(file, parsed, config));
    }
    context
        .ir
        .evidence
        .extend(rulepath_auth::normalize_route_evidence(
            &context.ir.routes,
            config,
        ));
}

fn collect_operation_facts(context: &mut ScanContext<'_>, config: &ResolvedConfig) {
    for file in &context.index.files {
        let Some(parsed) = parsed_for_file(&context.parsed_files, &file.relative_path) else {
            continue;
        };
        for adapter in rulepath_orms::built_in_data_layers() {
            context
                .ir
                .operations
                .extend(adapter.extract(file, parsed, config));
        }
        context
            .ir
            .operations
            .extend(rulepath_orms::extract_export_operations(
                file,
                &context.ir.routes,
            ));
    }
}

fn parsed_for_file<'a>(parsed_files: &'a [ParsedFile], file_id: &str) -> Option<&'a ParsedFile> {
    parsed_files.iter().find(|parsed| parsed.file_id == file_id)
}

fn attach_route_evidence(ir: &mut ProjectIr) {
    for evidence in &mut ir.evidence {
        if evidence.route_id.is_some() {
            continue;
        }
        if let Some(route) = ir
            .routes
            .iter()
            .find(|route| route.span.file_id.as_str() == evidence.span.file_id.as_str())
            .or_else(|| ir.routes.first())
        {
            evidence.route_id = Some(route.id.clone());
        }
    }
}

fn attach_call_paths(ir: &mut ProjectIr, trace_index: &TraceIndex) {
    for operation in &ir.operations {
        let operation_function = trace_index.function_for_span(&operation.span);
        let Some(route_match) =
            find_route_for_operation(ir, trace_index, operation, operation_function)
        else {
            continue;
        };
        let route = route_match.route;
        let mut frames = vec![CallFrame {
            function: route.handler.clone(),
            file: route.span.file_id.clone(),
            line: route.span.start.line,
        }];
        if operation.span.file_id.as_str() != route.span.file_id.as_str() {
            frames.push(CallFrame {
                function: operation_function
                    .map(|function| function.name.clone())
                    .unwrap_or_else(|| "service_or_repository".to_owned()),
                file: operation.span.file_id.clone(),
                line: operation.span.start.line,
            });
        }
        ir.call_paths.push(CallPath {
            id: format!("callpath:{}:{}", route.id, operation.id),
            route_id: route.id.clone(),
            sink_id: operation.id.clone(),
            frames,
            confidence: route_match.confidence,
        });
    }
}

fn rewrite_operation_sources_to_route_sources(ir: &mut ProjectIr) {
    let route_sources_by_operation = ir
        .operations
        .iter()
        .filter_map(|operation| {
            let call_path = ir.call_path_for_operation(&operation.id)?;
            if call_path.confidence == Confidence::Low {
                return None;
            }
            let route = ir.route_for_operation(&operation.id)?;
            let route_param = route
                .sources
                .iter()
                .find(|source| source.ends_with(":route_param"))
                .cloned();
            let body = route
                .sources
                .iter()
                .find(|source| source.ends_with(":body"))
                .cloned();
            Some((operation.id.clone(), route_param, body))
        })
        .collect::<Vec<_>>();

    for (operation_id, route_param, body) in route_sources_by_operation {
        let Some(operation) = ir
            .operations
            .iter_mut()
            .find(|operation| operation.id == operation_id)
        else {
            continue;
        };
        for filter in &mut operation.filters {
            if filter
                .source_id
                .as_deref()
                .is_some_and(|source| source.ends_with(":route_param"))
            {
                filter.source_id = route_param.clone();
            }
        }
        for field in &mut operation.mutation_fields {
            if field
                .source_id
                .as_deref()
                .is_some_and(|source| source.ends_with(":body"))
            {
                field.source_id = body.clone();
            }
        }
    }
}

fn find_route_for_operation<'a>(
    ir: &'a ProjectIr,
    trace_index: &TraceIndex,
    operation: &OperationFact,
    operation_function: Option<&FunctionSpan>,
) -> Option<RouteMatch<'a>> {
    if let Some(route) = ir
        .routes
        .iter()
        .find(|route| route.span.file_id.as_str() == operation.span.file_id.as_str())
    {
        return Some(RouteMatch {
            route,
            confidence: Confidence::High,
        });
    }

    if let Some(function) = operation_function {
        if let Some(route_call) = trace_index.route_calls.iter().find(|call| {
            call.callee == function.name
                || call
                    .callee
                    .rsplit('.')
                    .next()
                    .is_some_and(|last_segment| last_segment == function.name)
        }) {
            return ir
                .routes
                .iter()
                .find(|route| route.id == route_call.route_id)
                .map(|route| RouteMatch {
                    route,
                    confidence: Confidence::High,
                });
        }
    }

    ir.routes.first().map(|route| RouteMatch {
        route,
        confidence: Confidence::Low,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RouteMatch<'a> {
    route: &'a RouteFact,
    confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceIndex {
    functions: Vec<FunctionSpan>,
    route_calls: Vec<RouteCall>,
}

impl TraceIndex {
    fn function_for_span(&self, span: &SourceSpan) -> Option<&FunctionSpan> {
        self.functions.iter().find(|function| {
            function.file_id == span.file_id
                && function.start_line <= span.start.line
                && function.end_line >= span.start.line
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionSpan {
    file_id: String,
    name: String,
    start_line: usize,
    end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteCall {
    route_id: String,
    callee: String,
}

fn build_trace_index(
    index: &WorkspaceIndex,
    parsed_files: &[ParsedFile],
    ir: &ProjectIr,
) -> TraceIndex {
    let mut functions = parsed_files
        .iter()
        .flat_map(extract_functions)
        .collect::<Vec<_>>();
    assign_function_ends(index, &mut functions);
    let route_calls = ir
        .routes
        .iter()
        .filter_map(|route| {
            parsed_files
                .iter()
                .find(|parsed| parsed.file_id == route.span.file_id)
                .map(|parsed| extract_route_calls(parsed, route))
        })
        .flatten()
        .collect::<Vec<_>>();
    TraceIndex {
        functions,
        route_calls,
    }
}

fn extract_functions(parsed: &ParsedFile) -> Vec<FunctionSpan> {
    parsed
        .symbols
        .iter()
        .filter(|symbol| matches!(symbol.kind, SymbolKind::Function | SymbolKind::Method))
        .map(|symbol| FunctionSpan {
            file_id: parsed.file_id.clone(),
            name: symbol.name.clone(),
            start_line: symbol.span.start.line,
            end_line: usize::MAX,
        })
        .collect()
}

fn assign_function_ends(index: &WorkspaceIndex, functions: &mut [FunctionSpan]) {
    functions.sort_by(|left, right| {
        left.file_id
            .cmp(&right.file_id)
            .then(left.start_line.cmp(&right.start_line))
    });
    for i in 0..functions.len() {
        let file_line_count = index
            .files
            .iter()
            .find(|file| file.relative_path == functions[i].file_id)
            .map_or(functions[i].end_line, |file| file.text.lines().count());
        let next_start_in_file = functions.get(i + 1).and_then(|next| {
            (next.file_id == functions[i].file_id).then_some(next.start_line.saturating_sub(1))
        });
        functions[i].end_line = next_start_in_file.unwrap_or(file_line_count);
    }
}

fn extract_route_calls(parsed: &ParsedFile, route: &RouteFact) -> Vec<RouteCall> {
    let max_line = route.span.start.line.saturating_add(40);
    parsed
        .calls
        .iter()
        .filter(|call| {
            call.span.start.line >= route.span.start.line && call.span.start.line <= max_line
        })
        .filter(|call| is_trace_candidate(call.callee.as_str()))
        .map(|call| RouteCall {
            route_id: route.id.clone(),
            callee: call.callee.clone(),
        })
        .collect()
}

fn is_trace_candidate(callee: &str) -> bool {
    let last = callee.rsplit('.').next().unwrap_or(callee);
    !matches!(
        last,
        "Router"
            | "Depends"
            | "Response"
            | "json"
            | "sendStatus"
            | "requireAuth"
            | "requirePermission"
            | "require_permission"
            | "get_current_user"
            | "auth"
            | "patch"
            | "get"
            | "post"
            | "put"
            | "delete"
    )
}

fn sort_project_ir(ir: &mut ProjectIr) {
    ir.routes
        .sort_by(|left, right| span_key(&left.span).cmp(&span_key(&right.span)));
    ir.sources
        .sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
    ir.evidence
        .sort_by(|left, right| span_key(&left.span).cmp(&span_key(&right.span)));
    ir.operations
        .sort_by(|left, right| span_key(&left.span).cmp(&span_key(&right.span)));
    ir.call_paths
        .sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
}

fn span_key(span: &SourceSpan) -> (&str, usize, usize) {
    (span.file_id.as_str(), span.start.line, span.start.column)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rulepath_ir::{Language, Position};
    use rulepath_parsers::{CallFact, SymbolFact};
    use rulepath_workspace::SourceFile;

    #[test]
    fn parsed_fact_merging_is_deterministic() {
        let mut ir = ProjectIr {
            routes: vec![RouteFact {
                id: "route:b".to_owned(),
                framework: rulepath_ir::Framework::Express,
                language: Language::TypeScript,
                method: "GET".to_owned(),
                path: "/b".to_owned(),
                handler: "handler".to_owned(),
                span: SourceSpan {
                    file_id: "b.ts".to_owned(),
                    start: Position::new(2, 1),
                    end: Position::new(2, 1),
                },
                middleware: Vec::new(),
                sources: Vec::new(),
            }],
            ..ProjectIr::default()
        };
        sort_project_ir(&mut ir);
        assert_eq!(ir.routes[0].id, "route:b");
    }

    #[test]
    fn trace_index_uses_parsed_symbols_and_calls() {
        let parsed = ParsedFile {
            language: Language::TypeScript,
            file_id: "src/routes/invoices.ts".to_owned(),
            imports: Vec::new(),
            symbols: vec![SymbolFact {
                name: "routeHandler".to_owned(),
                kind: SymbolKind::Function,
                span: SourceSpan::single_line("src/routes/invoices.ts", 3),
            }],
            calls: vec![CallFact {
                callee: "updateInvoice".to_owned(),
                arguments: Vec::new(),
                span: SourceSpan::single_line("src/routes/invoices.ts", 4),
            }],
            suppressions: Vec::new(),
        };
        let index = WorkspaceIndex {
            root: ".".into(),
            files: vec![SourceFile {
                path: "src/routes/invoices.ts".into(),
                relative_path: "src/routes/invoices.ts".to_owned(),
                language: Language::TypeScript,
                text: "function routeHandler() {\nupdateInvoice()\n}".to_owned(),
            }],
        };
        let ir = ProjectIr {
            routes: vec![RouteFact {
                id: "route:test".to_owned(),
                framework: rulepath_ir::Framework::Express,
                language: Language::TypeScript,
                method: "PATCH".to_owned(),
                path: "/invoices/:id".to_owned(),
                handler: "routeHandler".to_owned(),
                span: SourceSpan::single_line("src/routes/invoices.ts", 3),
                middleware: Vec::new(),
                sources: Vec::new(),
            }],
            ..ProjectIr::default()
        };

        let trace = build_trace_index(&index, &[parsed], &ir);
        assert_eq!(trace.functions[0].name, "routeHandler");
        assert_eq!(trace.route_calls[0].callee, "updateInvoice");
    }

    #[test]
    fn express_prisma_fixture_builds_routes_operations_and_call_paths() {
        let config = rulepath_config::default_resolved_config();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures/express_prisma/unsafe");
        let index = rulepath_workspace::scan_workspace(root, &config).expect("fixture should scan");
        let ir = build_project_ir(&index, &config);

        assert!(!ir.routes.is_empty(), "routes: {:#?}", ir.routes);
        assert!(
            !ir.operations.is_empty(),
            "operations: {:#?}",
            ir.operations
        );
        assert!(
            !ir.call_paths.is_empty(),
            "call_paths: {:#?}",
            ir.call_paths
        );
    }
}
