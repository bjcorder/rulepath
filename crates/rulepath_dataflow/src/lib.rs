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
    attach_call_paths(&mut context.ir, &trace_index, config);
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
        if let Some(route) = nearest_same_file_route_for_line(
            ir.routes.as_slice(),
            evidence.span.file_id.as_str(),
            evidence.span.start.line,
        )
        .or_else(|| ir.routes.first())
        {
            evidence.route_id = Some(route.id.clone());
        }
    }
}

fn attach_call_paths(ir: &mut ProjectIr, trace_index: &TraceIndex, config: &ResolvedConfig) {
    for operation in &ir.operations {
        let operation_function = trace_index.function_for_span(&operation.span);
        let Some(route_match) =
            find_route_for_operation(ir, trace_index, operation, operation_function, config)
        else {
            continue;
        };
        let route = route_match.route;
        let frames = route_match
            .frames
            .unwrap_or_else(|| fallback_frames(route, operation, operation_function));
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
    config: &ResolvedConfig,
) -> Option<RouteMatch<'a>> {
    if let Some(route) = nearest_same_file_route(ir.routes.as_slice(), operation) {
        return Some(RouteMatch {
            route,
            confidence: Confidence::High,
            frames: None,
        });
    }

    if !config.raw.analysis.service_layer_tracing {
        return None;
    }

    if let Some(function) = operation_function {
        if let Some(route_trace) =
            trace_index.find_route_trace(function, config.raw.analysis.max_call_depth)
        {
            return ir
                .routes
                .iter()
                .find(|route| route.id == route_trace.route_id)
                .map(|route| RouteMatch {
                    route,
                    confidence: Confidence::High,
                    frames: Some(route_trace.frames),
                });
        }
    }
    None
}

fn nearest_same_file_route<'a>(
    routes: &'a [RouteFact],
    operation: &OperationFact,
) -> Option<&'a RouteFact> {
    nearest_same_file_route_for_line(
        routes,
        operation.span.file_id.as_str(),
        operation.span.start.line,
    )
}

fn nearest_same_file_route_for_line<'a>(
    routes: &'a [RouteFact],
    file_id: &str,
    line: usize,
) -> Option<&'a RouteFact> {
    routes
        .iter()
        .filter(|route| route.span.file_id.as_str() == file_id)
        .filter(|route| route.span.start.line <= line)
        .max_by_key(|route| route.span.start.line)
        .or_else(|| {
            routes
                .iter()
                .find(|route| route.span.file_id.as_str() == file_id)
        })
}

fn fallback_frames(
    route: &RouteFact,
    operation: &OperationFact,
    operation_function: Option<&FunctionSpan>,
) -> Vec<CallFrame> {
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
    frames
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteMatch<'a> {
    route: &'a RouteFact,
    confidence: Confidence,
    frames: Option<Vec<CallFrame>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceIndex {
    functions: Vec<FunctionSpan>,
    route_calls: Vec<RouteCall>,
    function_calls: Vec<FunctionCall>,
    imports: Vec<ResolvedImport>,
}

impl TraceIndex {
    fn function_for_span(&self, span: &SourceSpan) -> Option<&FunctionSpan> {
        self.functions.iter().find(|function| {
            function.file_id == span.file_id
                && function.start_line <= span.start.line
                && function.end_line >= span.start.line
        })
    }

    fn find_route_trace(&self, target: &FunctionSpan, max_depth: usize) -> Option<RouteTrace> {
        let mut matches = Vec::new();
        for route_call in &self.route_calls {
            for candidate in self.resolve_callee(&route_call.file_id, &route_call.callee) {
                let frames = vec![route_call.frame.clone(), function_frame(candidate)];
                self.walk_function(
                    candidate,
                    target,
                    max_depth,
                    frames,
                    &mut Vec::new(),
                    &mut matches,
                    route_call.route_id.clone(),
                );
            }
        }
        matches.sort_by(|left, right| {
            left.route_id
                .cmp(&right.route_id)
                .then(left.frames.len().cmp(&right.frames.len()))
        });
        matches.into_iter().next()
    }

    fn walk_function(
        &self,
        current: &FunctionSpan,
        target: &FunctionSpan,
        remaining_depth: usize,
        frames: Vec<CallFrame>,
        visited: &mut Vec<String>,
        matches: &mut Vec<RouteTrace>,
        route_id: String,
    ) {
        if current == target {
            matches.push(RouteTrace { route_id, frames });
            return;
        }
        if remaining_depth == 0 {
            return;
        }
        let current_key = current.key();
        if visited.iter().any(|item| item == &current_key) {
            return;
        }
        visited.push(current_key);
        for call in self
            .function_calls
            .iter()
            .filter(|call| call.caller == *current)
        {
            for next in self.resolve_callee(&call.caller.file_id, &call.callee) {
                let mut next_frames = frames.clone();
                next_frames.push(function_frame(next));
                self.walk_function(
                    next,
                    target,
                    remaining_depth.saturating_sub(1),
                    next_frames,
                    visited,
                    matches,
                    route_id.clone(),
                );
            }
        }
        visited.pop();
    }

    fn resolve_callee(&self, caller_file: &str, callee: &str) -> Vec<&FunctionSpan> {
        let last = callee.rsplit('.').next().unwrap_or(callee);
        let mut candidates = self
            .functions
            .iter()
            .filter(|function| function.file_id == caller_file && function.name == last)
            .collect::<Vec<_>>();
        for import in self
            .imports
            .iter()
            .filter(|import| import.file_id == caller_file)
        {
            if import.local_name == callee || import.local_name == last {
                candidates.extend(self.functions.iter().filter(|function| {
                    function.file_id == import.target_file_id
                        && (import.imported_name.as_deref() == Some(function.name.as_str())
                            || function.name == last
                            || import.imported_name.is_none())
                }));
            } else if callee.starts_with(&format!("{}.", import.local_name)) {
                candidates.extend(self.functions.iter().filter(|function| {
                    function.file_id == import.target_file_id && function.name == last
                }));
            }
        }
        candidates.sort_by(|left, right| {
            left.file_id
                .cmp(&right.file_id)
                .then(left.name.cmp(&right.name))
        });
        candidates.dedup_by(|left, right| left.file_id == right.file_id && left.name == right.name);
        candidates
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionSpan {
    file_id: String,
    name: String,
    start_line: usize,
    end_line: usize,
}

impl FunctionSpan {
    fn key(&self) -> String {
        format!("{}:{}:{}", self.file_id, self.name, self.start_line)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteCall {
    route_id: String,
    file_id: String,
    callee: String,
    frame: CallFrame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionCall {
    caller: FunctionSpan,
    callee: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedImport {
    file_id: String,
    local_name: String,
    imported_name: Option<String>,
    target_file_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteTrace {
    route_id: String,
    frames: Vec<CallFrame>,
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
    let function_calls = parsed_files
        .iter()
        .flat_map(|parsed| extract_function_calls(parsed, &functions))
        .collect::<Vec<_>>();
    let imports = parsed_files
        .iter()
        .flat_map(|parsed| resolve_imports(parsed, index))
        .collect::<Vec<_>>();
    TraceIndex {
        functions,
        route_calls,
        function_calls,
        imports,
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

fn extract_function_calls(parsed: &ParsedFile, functions: &[FunctionSpan]) -> Vec<FunctionCall> {
    let file_functions = functions
        .iter()
        .filter(|function| function.file_id == parsed.file_id)
        .collect::<Vec<_>>();
    parsed
        .calls
        .iter()
        .filter(|call| is_trace_candidate(call.callee.as_str()))
        .filter_map(|call| {
            let caller = file_functions
                .iter()
                .find(|function| {
                    function.start_line <= call.span.start.line
                        && function.end_line >= call.span.start.line
                })?
                .to_owned()
                .clone();
            Some(FunctionCall {
                caller,
                callee: call.callee.clone(),
            })
        })
        .collect()
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
            file_id: route.span.file_id.clone(),
            callee: call.callee.clone(),
            frame: CallFrame {
                function: route.handler.clone(),
                file: route.span.file_id.clone(),
                line: route.span.start.line,
            },
        })
        .collect()
}

fn resolve_imports(parsed: &ParsedFile, index: &WorkspaceIndex) -> Vec<ResolvedImport> {
    let mut resolved = Vec::new();
    for import in &parsed.imports {
        let target_file_id =
            resolve_module_path(parsed.file_id.as_str(), import.module.as_str(), index);
        if import.names.is_empty() {
            let Some(target_file_id) = target_file_id else {
                continue;
            };
            if let Some(local_name) = module_local_name(import.module.as_str()) {
                resolved.push(ResolvedImport {
                    file_id: parsed.file_id.clone(),
                    local_name,
                    imported_name: None,
                    target_file_id,
                });
            }
            continue;
        }
        for name in &import.names {
            let imported_module_target = if import.module == "." || import.module.ends_with('.') {
                resolve_module_path(
                    parsed.file_id.as_str(),
                    &format!("{}{}", import.module, name),
                    index,
                )
            } else {
                None
            };
            let Some(target_file_id) = imported_module_target
                .clone()
                .or_else(|| target_file_id.clone())
            else {
                continue;
            };
            resolved.push(ResolvedImport {
                file_id: parsed.file_id.clone(),
                local_name: name.clone(),
                imported_name: imported_module_target.is_none().then(|| name.clone()),
                target_file_id,
            });
        }
    }
    resolved
}

fn resolve_module_path(
    importer_file_id: &str,
    module: &str,
    index: &WorkspaceIndex,
) -> Option<String> {
    if !module.starts_with('.') {
        return None;
    }
    let importer_dir = importer_file_id.rsplit_once('/').map_or("", |(dir, _)| dir);
    let mut parts = importer_dir
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let normalized_module = normalize_relative_module(module);
    for part in normalized_module.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            item => parts.push(item),
        }
    }
    let stem = parts.join("/");
    [
        format!("{stem}.ts"),
        format!("{stem}.tsx"),
        format!("{stem}.js"),
        format!("{stem}.jsx"),
        format!("{stem}.py"),
        format!("{stem}/index.ts"),
        format!("{stem}/index.tsx"),
        format!("{stem}/__init__.py"),
    ]
    .into_iter()
    .find(|candidate| {
        index
            .files
            .iter()
            .any(|file| file.relative_path == *candidate)
    })
}

fn normalize_relative_module(module: &str) -> String {
    let leading_dots = module
        .chars()
        .take_while(|character| *character == '.')
        .count();
    let rest = module[leading_dots..].replace('.', "/");
    let dots = ".".repeat(leading_dots);
    if rest.is_empty() || rest.starts_with('/') {
        format!("{dots}{rest}")
    } else {
        format!("{dots}/{rest}")
    }
}

fn module_local_name(module: &str) -> Option<String> {
    module
        .trim_matches('.')
        .rsplit(['/', '.'])
        .find(|segment| !segment.is_empty())
        .map(ToOwned::to_owned)
}

fn function_frame(function: &FunctionSpan) -> CallFrame {
    CallFrame {
        function: function.name.clone(),
        file: function.file_id.clone(),
        line: function.start_line,
    }
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
    use rulepath_ir::{DataLayer, Language, OperationFact, OperationType, Position};
    use rulepath_parsers::{CallFact, ImportFact, SymbolFact};
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
    fn call_graph_resolves_imports_and_two_hop_paths() {
        let index = WorkspaceIndex {
            root: ".".into(),
            files: vec![
                SourceFile {
                    path: "src/routes/invoices.ts".into(),
                    relative_path: "src/routes/invoices.ts".to_owned(),
                    language: Language::TypeScript,
                    text: "router.patch('/x', () => updateInvoice())\n".to_owned(),
                },
                SourceFile {
                    path: "src/services/invoices.ts".into(),
                    relative_path: "src/services/invoices.ts".to_owned(),
                    language: Language::TypeScript,
                    text: "import { writeInvoice } from '../repositories/invoices'\n\nfunction updateInvoice() {\n  writeInvoice()\n}\n".to_owned(),
                },
                SourceFile {
                    path: "src/repositories/invoices.ts".into(),
                    relative_path: "src/repositories/invoices.ts".to_owned(),
                    language: Language::TypeScript,
                    text: "function writeInvoice() {\n  prisma.invoice.update()\n}\n".to_owned(),
                },
            ],
        };
        let parsed = vec![
            ParsedFile {
                language: Language::TypeScript,
                file_id: "src/routes/invoices.ts".to_owned(),
                imports: vec![ImportFact {
                    module: "../services/invoices".to_owned(),
                    names: vec!["updateInvoice".to_owned()],
                    span: SourceSpan::single_line("src/routes/invoices.ts", 1),
                }],
                symbols: Vec::new(),
                calls: vec![CallFact {
                    callee: "updateInvoice".to_owned(),
                    arguments: Vec::new(),
                    span: SourceSpan::single_line("src/routes/invoices.ts", 5),
                }],
                suppressions: Vec::new(),
            },
            ParsedFile {
                language: Language::TypeScript,
                file_id: "src/services/invoices.ts".to_owned(),
                imports: vec![ImportFact {
                    module: "../repositories/invoices".to_owned(),
                    names: vec!["writeInvoice".to_owned()],
                    span: SourceSpan::single_line("src/services/invoices.ts", 1),
                }],
                symbols: vec![SymbolFact {
                    name: "updateInvoice".to_owned(),
                    kind: SymbolKind::Function,
                    span: SourceSpan::single_line("src/services/invoices.ts", 3),
                }],
                calls: vec![CallFact {
                    callee: "writeInvoice".to_owned(),
                    arguments: Vec::new(),
                    span: SourceSpan::single_line("src/services/invoices.ts", 4),
                }],
                suppressions: Vec::new(),
            },
            ParsedFile {
                language: Language::TypeScript,
                file_id: "src/repositories/invoices.ts".to_owned(),
                imports: Vec::new(),
                symbols: vec![SymbolFact {
                    name: "writeInvoice".to_owned(),
                    kind: SymbolKind::Function,
                    span: SourceSpan::single_line("src/repositories/invoices.ts", 2),
                }],
                calls: Vec::new(),
                suppressions: Vec::new(),
            },
        ];
        let ir = ProjectIr {
            routes: vec![RouteFact {
                id: "route:test".to_owned(),
                framework: rulepath_ir::Framework::Express,
                language: Language::TypeScript,
                method: "PATCH".to_owned(),
                path: "/invoices/:id".to_owned(),
                handler: "inline_handler".to_owned(),
                span: SourceSpan::single_line("src/routes/invoices.ts", 4),
                middleware: Vec::new(),
                sources: Vec::new(),
            }],
            operations: vec![OperationFact {
                id: "sink:test".to_owned(),
                data_layer: DataLayer::Prisma,
                resource: "Invoice".to_owned(),
                operation: OperationType::Update,
                method: "prisma.invoice.update".to_owned(),
                filters: Vec::new(),
                mutation_fields: Vec::new(),
                bulk: false,
                span: SourceSpan::single_line("src/repositories/invoices.ts", 3),
            }],
            ..ProjectIr::default()
        };

        let trace = build_trace_index(&index, &parsed, &ir);
        let operation_function = trace
            .function_for_span(&ir.operations[0].span)
            .expect("operation should be inside repository function");
        let route_trace = trace
            .find_route_trace(operation_function, 2)
            .expect("two-hop route trace should resolve");
        assert_eq!(
            route_trace
                .frames
                .iter()
                .map(|frame| frame.function.as_str())
                .collect::<Vec<_>>(),
            vec!["inline_handler", "updateInvoice", "writeInvoice"]
        );
        assert!(trace.find_route_trace(operation_function, 0).is_none());
    }

    #[test]
    fn service_layer_tracing_can_be_disabled() {
        let mut config = rulepath_config::default_resolved_config();
        config.raw.analysis.service_layer_tracing = false;
        let ir = ProjectIr {
            routes: vec![RouteFact {
                id: "route:test".to_owned(),
                framework: rulepath_ir::Framework::Express,
                language: Language::TypeScript,
                method: "PATCH".to_owned(),
                path: "/invoices/:id".to_owned(),
                handler: "inline_handler".to_owned(),
                span: SourceSpan::single_line("src/routes/invoices.ts", 4),
                middleware: Vec::new(),
                sources: Vec::new(),
            }],
            operations: vec![OperationFact {
                id: "sink:test".to_owned(),
                data_layer: DataLayer::Prisma,
                resource: "Invoice".to_owned(),
                operation: OperationType::Update,
                method: "prisma.invoice.update".to_owned(),
                filters: Vec::new(),
                mutation_fields: Vec::new(),
                bulk: false,
                span: SourceSpan::single_line("src/services/invoices.ts", 3),
            }],
            ..ProjectIr::default()
        };
        let trace = TraceIndex {
            functions: vec![FunctionSpan {
                file_id: "src/services/invoices.ts".to_owned(),
                name: "updateInvoice".to_owned(),
                start_line: 1,
                end_line: 5,
            }],
            route_calls: vec![RouteCall {
                route_id: "route:test".to_owned(),
                file_id: "src/routes/invoices.ts".to_owned(),
                callee: "updateInvoice".to_owned(),
                frame: CallFrame {
                    function: "inline_handler".to_owned(),
                    file: "src/routes/invoices.ts".to_owned(),
                    line: 4,
                },
            }],
            function_calls: Vec::new(),
            imports: Vec::new(),
        };
        let operation_function = trace.function_for_span(&ir.operations[0].span);

        assert!(find_route_for_operation(
            &ir,
            &trace,
            &ir.operations[0],
            operation_function,
            &config
        )
        .is_none());
    }

    #[test]
    fn same_file_route_matching_uses_nearest_prior_route_span() {
        let operation = OperationFact {
            id: "sink:test".to_owned(),
            data_layer: DataLayer::DjangoOrm,
            resource: "Invoice".to_owned(),
            operation: OperationType::Read,
            method: "Invoice.objects.get".to_owned(),
            filters: Vec::new(),
            mutation_fields: Vec::new(),
            bulk: false,
            span: SourceSpan::single_line("app/views.py", 12),
        };
        let routes = vec![
            RouteFact {
                id: "route:first".to_owned(),
                framework: rulepath_ir::Framework::DjangoRestFramework,
                language: Language::Python,
                method: "GET".to_owned(),
                path: "/invoices".to_owned(),
                handler: "InvoiceViewSet.list".to_owned(),
                span: SourceSpan::single_line("app/views.py", 5),
                middleware: Vec::new(),
                sources: Vec::new(),
            },
            RouteFact {
                id: "route:second".to_owned(),
                framework: rulepath_ir::Framework::DjangoRestFramework,
                language: Language::Python,
                method: "GET".to_owned(),
                path: "/invoices/{pk}".to_owned(),
                handler: "InvoiceViewSet.get_object".to_owned(),
                span: SourceSpan::single_line("app/views.py", 10),
                middleware: Vec::new(),
                sources: Vec::new(),
            },
        ];

        let route = nearest_same_file_route(&routes, &operation)
            .expect("same-file route should be matched");
        assert_eq!(route.id, "route:second");
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
