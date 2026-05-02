use rulepath_config::ResolvedConfig;
use rulepath_ir::{
    CallFrame, CallPath, Confidence, DataLayer, EvidenceFact, EvidenceKind, FilterFact, Framework,
    Language, MutationFieldFact, OperationFact, OperationType, ProjectIr, RouteFact, SourceFact,
    SourceKind, SourceSpan,
};
use rulepath_workspace::{line_number_for_offset, SourceFile, WorkspaceIndex};

pub fn build_project_ir(index: &WorkspaceIndex, config: &ResolvedConfig) -> ProjectIr {
    let mut ir = ProjectIr::default();

    for file in &index.files {
        detect_routes(file, &mut ir);
    }

    for file in &index.files {
        detect_evidence(file, &mut ir);
        detect_operations(file, config, &mut ir);
    }

    attach_route_evidence(&mut ir);
    attach_call_paths(&mut ir);
    ir
}

fn detect_routes(file: &SourceFile, ir: &mut ProjectIr) {
    let routes_before = ir.routes.len();
    for (line_index, line) in file.text.lines().enumerate() {
        let line_number = line_index + 1;
        if file.language == Language::TypeScript {
            if let Some((method, path)) = detect_express_line(line) {
                push_route(file, ir, Framework::Express, method, path, line_number);
            }
            if let Some((method, path)) = detect_nextjs_line(file, line) {
                push_route(file, ir, Framework::NextJs, method, path, line_number);
            }
        }

        if file.language == Language::Python {
            if let Some((method, path)) = detect_fastapi_line(line) {
                push_route(file, ir, Framework::FastApi, method, path, line_number);
            }
            if line.contains("ModelViewSet") || line.contains("APIView") {
                push_route(
                    file,
                    ir,
                    Framework::DjangoRestFramework,
                    "GET".to_owned(),
                    inferred_django_path(file),
                    line_number,
                );
            }
        }
    }

    if file.language == Language::TypeScript && ir.routes.len() == routes_before {
        if let Some((method, path, line_number)) = detect_multiline_express_route(file) {
            push_route(file, ir, Framework::Express, method, path, line_number);
        }
    }
}

fn detect_express_line(line: &str) -> Option<(String, String)> {
    for method in ["get", "post", "put", "patch", "delete"] {
        let router_call = format!("router.{method}(");
        let app_call = format!("app.{method}(");
        if line.contains(&router_call) || line.contains(&app_call) {
            return Some((method.to_ascii_uppercase(), extract_first_string(line)?));
        }
    }
    None
}

fn detect_fastapi_line(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    if !(trimmed.starts_with("@router.") || trimmed.starts_with("@app.")) {
        return None;
    }
    for method in ["get", "post", "put", "patch", "delete"] {
        if trimmed.contains(&format!(".{method}(")) {
            return Some((method.to_ascii_uppercase(), extract_first_string(trimmed)?));
        }
    }
    None
}

fn detect_nextjs_line(file: &SourceFile, line: &str) -> Option<(String, String)> {
    if !file.relative_path.contains("app/api/") && !file.relative_path.contains("pages/api/") {
        return None;
    }
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        if line.contains(&format!("function {method}")) || line.contains(&format!("const {method}"))
        {
            return Some((
                method.to_owned(),
                path_from_nextjs_file(file.relative_path.as_str()),
            ));
        }
    }
    None
}

fn detect_multiline_express_route(file: &SourceFile) -> Option<(String, String, usize)> {
    for method in ["get", "post", "put", "patch", "delete"] {
        for needle in [format!("router.{method}("), format!("app.{method}(")] {
            if let Some((offset, _)) = file.text.match_indices(&needle).next() {
                let window = surrounding_window(&file.text, offset, 300);
                let path = extract_first_string(&window)?;
                let line = line_number_for_offset(&file.text, offset);
                return Some((method.to_ascii_uppercase(), path, line));
            }
        }
    }
    None
}

fn push_route(
    file: &SourceFile,
    ir: &mut ProjectIr,
    framework: Framework,
    method: String,
    path: String,
    line_number: usize,
) {
    let id = format!("route:{framework:?}:{method}:{path}:{}", ir.routes.len());
    let body_source = format!("source:{}:body", file.relative_path);
    let param_source = format!("source:{}:route_param", file.relative_path);
    ir.sources.push(SourceFact {
        id: body_source.clone(),
        kind: SourceKind::Body,
        name: "body".to_owned(),
        expression: body_expression(framework),
        controlled_by_request: true,
        span: SourceSpan::single_line(file.relative_path.as_str(), line_number),
    });
    ir.sources.push(SourceFact {
        id: param_source.clone(),
        kind: SourceKind::RouteParam,
        name: "id".to_owned(),
        expression: param_expression(framework),
        controlled_by_request: true,
        span: SourceSpan::single_line(file.relative_path.as_str(), line_number),
    });
    ir.routes.push(RouteFact {
        id,
        framework,
        language: file.language,
        method,
        path,
        handler: "statically_discovered_handler".to_owned(),
        span: SourceSpan::single_line(file.relative_path.as_str(), line_number),
        middleware: Vec::new(),
        sources: vec![param_source, body_source],
    });
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

fn detect_evidence(file: &SourceFile, ir: &mut ProjectIr) {
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
        (
            "auth()",
            EvidenceKind::Authentication,
            "authentication:auth",
        ),
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

    for (needle, kind, label) in evidence_specs {
        for (offset, _) in file.text.match_indices(needle) {
            let line = line_number_for_offset(&file.text, offset);
            ir.evidence.push(EvidenceFact {
                id: format!("evidence:{}:{line}:{needle}", file.relative_path),
                kind,
                label: label.to_owned(),
                expression: needle.to_owned(),
                confidence: Confidence::High,
                route_id: None,
                sink_id: None,
                span: SourceSpan::single_line(file.relative_path.as_str(), line),
            });
        }
    }
}

fn detect_operations(file: &SourceFile, config: &ResolvedConfig, ir: &mut ProjectIr) {
    detect_prisma_operations(file, config, ir);
    detect_sqlalchemy_operations(file, config, ir);
    detect_django_orm_operations(file, config, ir);
    detect_export_operations(file, ir);
}

fn detect_prisma_operations(file: &SourceFile, config: &ResolvedConfig, ir: &mut ProjectIr) {
    for (offset, _) in file.text.match_indices("prisma.") {
        let after = &file.text[offset + "prisma.".len()..];
        let Some((model, method)) = parse_property_call(after) else {
            continue;
        };
        let Some(operation) = prisma_operation(&method) else {
            continue;
        };
        let line = line_number_for_offset(&file.text, offset);
        let window = surrounding_window(&file.text, offset, 500);
        let resource = to_resource_name(&model);
        let filters = extract_filters(&resource, &window, config, file);
        let mutation_fields = extract_mutation_fields(&window, file);
        ir.operations.push(OperationFact {
            id: format!("sink:prisma.{model}.{method}:{}:{line}", file.relative_path),
            data_layer: DataLayer::Prisma,
            resource,
            operation,
            method: format!("prisma.{model}.{method}"),
            filters,
            mutation_fields,
            bulk: matches!(
                operation,
                OperationType::BulkUpdate | OperationType::BulkDelete
            ),
            span: SourceSpan::single_line(file.relative_path.as_str(), line),
        });
    }
}

fn detect_sqlalchemy_operations(file: &SourceFile, config: &ResolvedConfig, ir: &mut ProjectIr) {
    for marker in ["session.get(", "select(", "update(", "delete("] {
        for (offset, _) in file.text.match_indices(marker) {
            let after = &file.text[offset + marker.len()..];
            let resource = after
                .chars()
                .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
                .collect::<String>();
            if resource.is_empty() {
                continue;
            }
            let line = line_number_for_offset(&file.text, offset);
            let window = surrounding_window(&file.text, offset, 500);
            let operation = if marker == "delete(" {
                OperationType::Delete
            } else if marker == "update("
                || window.contains("session.commit")
                || window.contains("body.status")
            {
                OperationType::Update
            } else {
                OperationType::Read
            };
            ir.operations.push(OperationFact {
                id: format!(
                    "sink:sqlalchemy.{resource}.{marker}:{}:{line}",
                    file.relative_path
                ),
                data_layer: DataLayer::SqlAlchemy,
                resource: resource.clone(),
                operation,
                method: marker.trim_end_matches('(').to_owned(),
                filters: extract_filters(&resource, &window, config, file),
                mutation_fields: extract_mutation_fields(&window, file),
                bulk: marker == "update(" || marker == "delete(",
                span: SourceSpan::single_line(file.relative_path.as_str(), line),
            });
        }
    }
}

fn detect_django_orm_operations(file: &SourceFile, config: &ResolvedConfig, ir: &mut ProjectIr) {
    for (offset, _) in file.text.match_indices(".objects.") {
        let before = &file.text[..offset];
        let resource = before
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .next_back()
            .unwrap_or_default()
            .to_owned();
        if resource.is_empty() {
            continue;
        }
        let after = &file.text[offset + ".objects.".len()..];
        let method = after
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect::<String>();
        let Some(operation) = django_operation(&method) else {
            continue;
        };
        let line = line_number_for_offset(&file.text, offset);
        let window = surrounding_window(&file.text, offset, 500);
        ir.operations.push(OperationFact {
            id: format!(
                "sink:django_orm.{resource}.{method}:{}:{line}",
                file.relative_path
            ),
            data_layer: DataLayer::DjangoOrm,
            resource: resource.clone(),
            operation,
            method: format!("{resource}.objects.{method}"),
            filters: extract_filters(&resource, &window, config, file),
            mutation_fields: extract_mutation_fields(&window, file),
            bulk: matches!(
                operation,
                OperationType::BulkUpdate | OperationType::BulkDelete
            ),
            span: SourceSpan::single_line(file.relative_path.as_str(), line),
        });
    }
}

fn detect_export_operations(file: &SourceFile, ir: &mut ProjectIr) {
    let lower_text = file.text.to_ascii_lowercase();
    let export_like = [
        "/export",
        "download",
        "report",
        "text/csv",
        "application/pdf",
    ];
    if !export_like.iter().any(|needle| lower_text.contains(needle)) {
        return;
    }
    if let Some(route) = ir
        .routes
        .iter()
        .find(|route| route.span.file_id.as_str() == file.relative_path.as_str())
    {
        let operation = if route.path.contains("download") {
            OperationType::Download
        } else if route.path.contains("report") {
            OperationType::Report
        } else {
            OperationType::Export
        };
        ir.operations.push(OperationFact {
            id: format!("sink:export:{}:{}", file.relative_path, route.method),
            data_layer: DataLayer::Unknown,
            resource: infer_resource_from_text(&file.text).unwrap_or_else(|| "Unknown".to_owned()),
            operation,
            method: "response_export".to_owned(),
            filters: Vec::new(),
            mutation_fields: Vec::new(),
            bulk: true,
            span: route.span.clone(),
        });
    }
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

fn attach_call_paths(ir: &mut ProjectIr) {
    for operation in &ir.operations {
        let Some(route) = ir
            .routes
            .iter()
            .find(|route| route.span.file_id.as_str() == operation.span.file_id.as_str())
            .or_else(|| ir.routes.first())
        else {
            continue;
        };
        let mut frames = vec![CallFrame {
            function: route.handler.clone(),
            file: route.span.file_id.clone(),
            line: route.span.start.line,
        }];
        if operation.span.file_id.as_str() != route.span.file_id.as_str() {
            frames.push(CallFrame {
                function: "service_or_repository".to_owned(),
                file: operation.span.file_id.clone(),
                line: operation.span.start.line,
            });
        }
        ir.call_paths.push(CallPath {
            id: format!("callpath:{}:{}", route.id, operation.id),
            route_id: route.id.clone(),
            sink_id: operation.id.clone(),
            frames,
            confidence: Confidence::Medium,
        });
    }
}

fn extract_first_string(line: &str) -> Option<String> {
    let quote_index = line.find('"').or_else(|| line.find('\''))?;
    let quote = line.as_bytes()[quote_index] as char;
    let rest = &line[quote_index + 1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_owned())
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

fn parse_property_call(text: &str) -> Option<(String, String)> {
    let mut parts = text.splitn(3, '.');
    let model = parts
        .next()?
        .chars()
        .take_while(is_identifier_char)
        .collect::<String>();
    let method_text = parts.next()?;
    let method = method_text
        .chars()
        .take_while(is_identifier_char)
        .collect::<String>();
    if model.is_empty() || method.is_empty() {
        None
    } else {
        Some((model, method))
    }
}

fn is_identifier_char(character: &char) -> bool {
    character.is_ascii_alphanumeric() || *character == '_'
}

fn prisma_operation(method: &str) -> Option<OperationType> {
    match method {
        "findUnique" | "findFirst" | "findMany" => Some(OperationType::Read),
        "create" => Some(OperationType::Create),
        "update" | "upsert" => Some(OperationType::Update),
        "delete" => Some(OperationType::Delete),
        "updateMany" => Some(OperationType::BulkUpdate),
        "deleteMany" => Some(OperationType::BulkDelete),
        _ => None,
    }
}

fn django_operation(method: &str) -> Option<OperationType> {
    match method {
        "get" | "filter" | "all" => Some(OperationType::Read),
        "create" => Some(OperationType::Create),
        "update" => Some(OperationType::BulkUpdate),
        "delete" => Some(OperationType::BulkDelete),
        _ => None,
    }
}

fn to_resource_name(model: &str) -> String {
    let mut characters = model.chars();
    let Some(first) = characters.next() else {
        return "Unknown".to_owned();
    };
    format!(
        "{}{}",
        first.to_ascii_uppercase(),
        characters.collect::<String>()
    )
}

fn surrounding_window(text: &str, offset: usize, radius: usize) -> String {
    let start = offset.saturating_sub(radius);
    let end = (offset + radius).min(text.len());
    text[start..end].to_owned()
}

fn extract_filters(
    resource: &str,
    window: &str,
    config: &ResolvedConfig,
    file: &SourceFile,
) -> Vec<FilterFact> {
    let mut filters = Vec::new();
    if contains_id_filter(window) {
        filters.push(FilterFact {
            field: "id".to_owned(),
            value: "request-controlled id".to_owned(),
            source_id: Some(format!("source:{}:route_param", file.relative_path)),
        });
    }
    for field in config.tenant_fields_for(resource) {
        if window.contains(&field) {
            filters.push(FilterFact {
                field,
                value: "current principal scope".to_owned(),
                source_id: None,
            });
        }
    }
    filters
}

fn contains_id_filter(window: &str) -> bool {
    window.contains(" id")
        || window.contains("id:")
        || window.contains(".id")
        || window.contains("_id")
        || window.contains("invoice_id")
        || window.contains("client_id")
}

fn extract_mutation_fields(window: &str, file: &SourceFile) -> Vec<MutationFieldFact> {
    let mut fields = Vec::new();
    if window.contains("data: body")
        || window.contains("data: req.body")
        || window.contains("data: request.body")
        || window.contains("request.data")
    {
        fields.push(MutationFieldFact {
            field: "*".to_owned(),
            value: "request body".to_owned(),
            source_id: Some(format!("source:{}:body", file.relative_path)),
        });
    }
    for field in [
        "status",
        "state",
        "role",
        "tenant_id",
        "tenantId",
        "amount",
        "total",
        "approved_by",
        "approvedBy",
    ] {
        if window.contains(field) && (window.contains("body") || window.contains("request.data")) {
            fields.push(MutationFieldFact {
                field: field.to_owned(),
                value: format!("body.{field}"),
                source_id: Some(format!("source:{}:body", file.relative_path)),
            });
        }
    }
    fields
}

fn infer_resource_from_text(text: &str) -> Option<String> {
    ["Invoice", "Client", "User", "Order", "Payment"]
        .iter()
        .find(|resource| {
            text.contains(**resource)
                || text
                    .to_ascii_lowercase()
                    .contains(&resource.to_ascii_lowercase())
        })
        .map(|resource| (*resource).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nextjs_path_is_normalized() {
        assert_eq!(
            path_from_nextjs_file("app/api/invoices/[invoiceId]/route.ts"),
            "/invoices/:invoiceId"
        );
    }
}
