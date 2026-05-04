use rulepath_config::ResolvedConfig;
use rulepath_ir::{
    DataLayer, FilterFact, MutationFieldFact, OperationFact, OperationType, RouteFact, SourceSpan,
};
use rulepath_parsers::ParsedFile;
use rulepath_workspace::SourceFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataLayerDescriptor {
    pub id: DataLayer,
    pub name: &'static str,
}

pub trait DataLayerAdapter {
    fn descriptor(&self) -> DataLayerDescriptor;
    fn extract(
        &self,
        file: &SourceFile,
        parsed: &ParsedFile,
        config: &ResolvedConfig,
    ) -> Vec<OperationFact>;
}

#[derive(Debug, Clone, Copy)]
struct BuiltInDataLayerAdapter {
    descriptor: DataLayerDescriptor,
}

impl DataLayerAdapter for BuiltInDataLayerAdapter {
    fn descriptor(&self) -> DataLayerDescriptor {
        self.descriptor
    }

    fn extract(
        &self,
        file: &SourceFile,
        parsed: &ParsedFile,
        config: &ResolvedConfig,
    ) -> Vec<OperationFact> {
        match self.descriptor.id {
            DataLayer::Prisma => extract_prisma_operations(file, parsed, config),
            DataLayer::SqlAlchemy => extract_sqlalchemy_operations(file, parsed, config),
            DataLayer::DjangoOrm => extract_django_orm_operations(file, parsed, config),
            DataLayer::Unknown => Vec::new(),
        }
    }
}

static BUILT_IN_DATA_LAYER_ADAPTERS: &[BuiltInDataLayerAdapter] = &[
    BuiltInDataLayerAdapter {
        descriptor: DataLayerDescriptor {
            id: DataLayer::Prisma,
            name: "prisma",
        },
    },
    BuiltInDataLayerAdapter {
        descriptor: DataLayerDescriptor {
            id: DataLayer::SqlAlchemy,
            name: "sqlalchemy",
        },
    },
    BuiltInDataLayerAdapter {
        descriptor: DataLayerDescriptor {
            id: DataLayer::DjangoOrm,
            name: "django_orm",
        },
    },
];

#[must_use]
pub fn built_in_data_layers() -> Vec<&'static dyn DataLayerAdapter> {
    BUILT_IN_DATA_LAYER_ADAPTERS
        .iter()
        .map(|adapter| adapter as &dyn DataLayerAdapter)
        .collect()
}

#[must_use]
pub fn built_in_data_layer_descriptors() -> Vec<DataLayerDescriptor> {
    BUILT_IN_DATA_LAYER_ADAPTERS
        .iter()
        .map(|adapter| adapter.descriptor())
        .collect()
}

#[must_use]
pub fn extract_export_operations(file: &SourceFile, routes: &[RouteFact]) -> Vec<OperationFact> {
    let lower_text = file.text.to_ascii_lowercase();
    let export_like = [
        "/export",
        "download",
        "report",
        "text/csv",
        "application/pdf",
    ];
    if !export_like.iter().any(|needle| lower_text.contains(needle)) {
        return Vec::new();
    }
    routes
        .iter()
        .find(|route| route.span.file_id.as_str() == file.relative_path.as_str())
        .map(|route| {
            let operation = if route.path.contains("download") {
                OperationType::Download
            } else if route.path.contains("report") {
                OperationType::Report
            } else {
                OperationType::Export
            };
            OperationFact {
                id: format!("sink:export:{}:{}", file.relative_path, route.method),
                data_layer: DataLayer::Unknown,
                resource: infer_resource_from_text(&file.text)
                    .unwrap_or_else(|| "Unknown".to_owned()),
                operation,
                method: "response_export".to_owned(),
                filters: Vec::new(),
                mutation_fields: Vec::new(),
                bulk: true,
                span: route.span.clone(),
            }
        })
        .into_iter()
        .collect()
}

fn extract_prisma_operations(
    file: &SourceFile,
    parsed: &ParsedFile,
    config: &ResolvedConfig,
) -> Vec<OperationFact> {
    let mut operations = Vec::new();
    let client_names = prisma_client_names(file);
    for call in &parsed.calls {
        let mut parts = call.callee.split('.');
        let Some(client) = parts.next() else {
            continue;
        };
        if !client_names.iter().any(|name| name == client) {
            continue;
        };
        let Some(model) = parts.next() else {
            continue;
        };
        let Some(method) = parts.next() else {
            continue;
        };
        let Some(operation) = prisma_operation(method) else {
            continue;
        };
        let window = surrounding_window_for_line(&file.text, call.span.start.line, 500);
        let resource = to_resource_name(model);
        operations.push(OperationFact {
            id: format!(
                "sink:prisma.{model}.{method}:{}:{}",
                file.relative_path, call.span.start.line
            ),
            data_layer: DataLayer::Prisma,
            resource: resource.clone(),
            operation,
            method: format!("prisma.{model}.{method}"),
            filters: extract_prisma_filters(
                &resource,
                &call.arguments.join(", "),
                &window,
                config,
                file,
            ),
            mutation_fields: extract_prisma_mutation_fields(&call.arguments.join(", "), file),
            bulk: matches!(
                operation,
                OperationType::BulkUpdate | OperationType::BulkDelete
            ),
            span: call.span.clone(),
        });
    }
    operations
}

fn prisma_client_names(file: &SourceFile) -> Vec<String> {
    let mut names = vec!["prisma".to_owned()];
    for line in file.text.lines() {
        let trimmed = line.trim();
        if !trimmed.contains("PrismaClient") {
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("const ")
            .or_else(|| trimmed.strip_prefix("let "))
            .or_else(|| trimmed.strip_prefix("var "))
        {
            if let Some(name) = rest
                .split('=')
                .next()
                .map(str::trim)
                .filter(|name| !name.is_empty())
            {
                names.push(name.to_owned());
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

fn extract_prisma_filters(
    resource: &str,
    arguments: &str,
    window: &str,
    config: &ResolvedConfig,
    file: &SourceFile,
) -> Vec<FilterFact> {
    let where_section = object_section(arguments, "where").unwrap_or(arguments);
    let mut filters = Vec::new();
    if contains_id_filter(where_section) {
        filters.push(FilterFact {
            field: "id".to_owned(),
            value: request_controlled_value(where_section),
            source_id: Some(format!("source:{}:route_param", file.relative_path)),
        });
    }
    for field in config.tenant_fields_for(resource) {
        if where_section.contains(&field) || window.contains(&field) {
            filters.push(FilterFact {
                field,
                value: "current principal scope".to_owned(),
                source_id: None,
            });
        }
    }
    filters
}

fn extract_prisma_mutation_fields(arguments: &str, file: &SourceFile) -> Vec<MutationFieldFact> {
    let Some(data_section) = object_section(arguments, "data") else {
        return Vec::new();
    };
    extract_mutation_fields(data_section, file)
}

fn extract_sqlalchemy_operations(
    file: &SourceFile,
    parsed: &ParsedFile,
    config: &ResolvedConfig,
) -> Vec<OperationFact> {
    let mut operations = Vec::new();
    for call in &parsed.calls {
        let Some((resource, method, operation_hint)) = sqlalchemy_call_shape(call) else {
            continue;
        };
        let window = surrounding_window_for_line(&file.text, call.span.start.line, 500);
        let operation = if operation_hint == OperationType::Read
            && window.contains("session.commit")
            && contains_body_assignment(&window)
        {
            OperationType::Update
        } else {
            operation_hint
        };
        operations.push(OperationFact {
            id: format!(
                "sink:sqlalchemy.{resource}.{method}:{}:{}",
                file.relative_path, call.span.start.line
            ),
            data_layer: DataLayer::SqlAlchemy,
            resource: resource.clone(),
            operation,
            method,
            filters: extract_sqlalchemy_filters(&resource, &call.arguments, &window, config, file),
            mutation_fields: extract_mutation_fields(&window, file),
            bulk: matches!(
                operation,
                OperationType::BulkUpdate | OperationType::BulkDelete
            ),
            span: call.span.clone(),
        });
    }
    operations
}

fn sqlalchemy_call_shape(
    call: &rulepath_parsers::CallFact,
) -> Option<(String, String, OperationType)> {
    match call.callee.as_str() {
        "session.get" => call.arguments.first().map(|resource| {
            (
                resource.trim().to_owned(),
                "session.get".to_owned(),
                OperationType::Read,
            )
        }),
        "select" => call.arguments.first().map(|resource| {
            (
                resource.trim().to_owned(),
                "select".to_owned(),
                OperationType::Read,
            )
        }),
        "update" => call.arguments.first().map(|resource| {
            (
                resource.trim().to_owned(),
                "update".to_owned(),
                OperationType::BulkUpdate,
            )
        }),
        "delete" => call.arguments.first().map(|resource| {
            (
                resource.trim().to_owned(),
                "delete".to_owned(),
                OperationType::BulkDelete,
            )
        }),
        "session.execute" => call
            .arguments
            .first()
            .and_then(|argument| sqlalchemy_execute_shape(argument)),
        _ => None,
    }
}

fn sqlalchemy_execute_shape(argument: &str) -> Option<(String, String, OperationType)> {
    for (prefix, operation) in [
        ("select(", OperationType::Read),
        ("update(", OperationType::BulkUpdate),
        ("delete(", OperationType::BulkDelete),
    ] {
        if let Some(rest) = argument.trim().strip_prefix(prefix) {
            let resource = rest.split([')', ',', '.']).next()?.trim();
            if !resource.is_empty() {
                return Some((
                    resource.to_owned(),
                    prefix.trim_end_matches('(').to_owned(),
                    operation,
                ));
            }
        }
    }
    None
}

fn extract_sqlalchemy_filters(
    resource: &str,
    arguments: &[String],
    window: &str,
    config: &ResolvedConfig,
    file: &SourceFile,
) -> Vec<FilterFact> {
    let mut filters = Vec::new();
    if arguments
        .get(1)
        .is_some_and(|argument| is_request_controlled_id_expression(argument))
        || contains_id_filter(window)
    {
        filters.push(FilterFact {
            field: "id".to_owned(),
            value: arguments
                .get(1)
                .cloned()
                .unwrap_or_else(|| request_controlled_value(window)),
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

fn is_request_controlled_id_expression(argument: &str) -> bool {
    let trimmed = argument.trim();
    trimmed == "id"
        || trimmed.ends_with("_id")
        || trimmed.ends_with("Id")
        || trimmed.contains("params")
}

fn contains_body_assignment(window: &str) -> bool {
    window
        .lines()
        .any(|line| line.contains(" = body.") || line.contains(" = request.data"))
}

fn extract_django_orm_operations(
    file: &SourceFile,
    parsed: &ParsedFile,
    config: &ResolvedConfig,
) -> Vec<OperationFact> {
    let mut operations = Vec::new();
    for call in &parsed.calls {
        if let Some(shape) = django_call_shape(call.callee.as_str()) {
            let window = surrounding_window_for_line(&file.text, call.span.start.line, 500);
            operations.push(OperationFact {
                id: format!(
                    "sink:django_orm.{}.{}:{}:{}",
                    shape.resource, shape.method, file.relative_path, call.span.start.line
                ),
                data_layer: DataLayer::DjangoOrm,
                resource: shape.resource.clone(),
                operation: shape.operation,
                method: shape.method,
                filters: extract_django_filters(
                    &shape.resource,
                    &call.arguments.join(", "),
                    call.callee.as_str(),
                    &window,
                    config,
                    file,
                ),
                mutation_fields: extract_django_mutation_fields(
                    &call.arguments.join(", "),
                    &window,
                    file,
                ),
                bulk: matches!(
                    shape.operation,
                    OperationType::BulkUpdate | OperationType::BulkDelete
                ),
                span: call.span.clone(),
            });
        } else if let Some(shape) = django_save_shape(call.callee.as_str(), &file.text) {
            let window = surrounding_window_for_line(&file.text, call.span.start.line, 500);
            operations.push(OperationFact {
                id: format!(
                    "sink:django_orm.{}.{}:{}:{}",
                    shape.resource, shape.method, file.relative_path, call.span.start.line
                ),
                data_layer: DataLayer::DjangoOrm,
                resource: shape.resource.clone(),
                operation: shape.operation,
                method: shape.method,
                filters: extract_filters(&shape.resource, &window, config, file),
                mutation_fields: extract_django_mutation_fields("", &window, file),
                bulk: false,
                span: call.span.clone(),
            });
        }
    }
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
        let line = rulepath_workspace::line_number_for_offset(&file.text, offset);
        if operations
            .iter()
            .any(|operation| operation.span.start.line == line && operation.resource == resource)
        {
            continue;
        }
        let window = surrounding_window_for_offset(&file.text, offset, 500);
        operations.push(OperationFact {
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
    operations.sort_by(|left, right| {
        left.span
            .start
            .line
            .cmp(&right.span.start.line)
            .then(left.id.cmp(&right.id))
    });
    operations.dedup_by(|left, right| left.id == right.id);
    operations
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DjangoOperationShape {
    resource: String,
    method: String,
    operation: OperationType,
}

fn django_call_shape(callee: &str) -> Option<DjangoOperationShape> {
    let objects_index = callee.find(".objects.")?;
    let resource = callee[..objects_index]
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_owned();
    if resource.is_empty() {
        return None;
    }
    let after_objects = &callee[objects_index + ".objects.".len()..];
    let method = django_method_from_chain(after_objects)?;
    let operation = django_operation(method)?;
    let method = format!("{resource}.objects.{method}");
    Some(DjangoOperationShape {
        resource,
        method,
        operation,
    })
}

fn django_method_from_chain(chain: &str) -> Option<&'static str> {
    for method in ["update", "delete"] {
        if chain.starts_with(method) || chain.contains(&format!(".{method}")) {
            return Some(method);
        }
    }
    ["get", "filter", "all", "create"]
        .into_iter()
        .find(|&method| chain.starts_with(method))
}

fn django_save_shape(callee: &str, text: &str) -> Option<DjangoOperationShape> {
    if !callee.ends_with(".save") && callee != "save" {
        return None;
    }
    let resource = serializer_resource(text).or_else(|| infer_resource_from_text(text))?;
    let operation = if text.contains("instance=") || text.contains(".objects.get") {
        OperationType::Update
    } else {
        OperationType::Create
    };
    Some(DjangoOperationShape {
        resource,
        method: callee.to_owned(),
        operation,
    })
}

fn serializer_resource(text: &str) -> Option<String> {
    for line in text.lines() {
        let Some(index) = line.find("Serializer") else {
            continue;
        };
        let before = &line[..index];
        let name = before
            .rsplit(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .find(|part| !part.is_empty())?;
        if !name.is_empty() {
            return Some(name.to_owned());
        }
    }
    None
}

fn extract_django_filters(
    resource: &str,
    arguments: &str,
    callee: &str,
    window: &str,
    config: &ResolvedConfig,
    file: &SourceFile,
) -> Vec<FilterFact> {
    let filter_text = format!("{arguments}\n{callee}\n{window}");
    let mut filters = Vec::new();
    if contains_id_filter(filter_text.as_str())
        || filter_text.contains("kwargs")
        || filter_text.contains("\"pk\"")
        || filter_text.contains("'pk'")
        || filter_text.contains("query_params")
    {
        filters.push(FilterFact {
            field: "id".to_owned(),
            value: request_controlled_value(filter_text.as_str()),
            source_id: Some(format!("source:{}:route_param", file.relative_path)),
        });
    }
    for field in config.tenant_fields_for(resource) {
        if filter_text.contains(&field) {
            filters.push(FilterFact {
                field,
                value: "current principal scope".to_owned(),
                source_id: None,
            });
        }
    }
    filters.sort_by(|left, right| left.field.cmp(&right.field));
    filters.dedup_by(|left, right| left.field == right.field && left.source_id == right.source_id);
    filters
}

fn extract_django_mutation_fields(
    arguments: &str,
    window: &str,
    file: &SourceFile,
) -> Vec<MutationFieldFact> {
    let text = format!("{arguments}\n{window}");
    let mut fields = extract_mutation_fields(text.as_str(), file);
    if text.contains("serializer")
        && (text.contains("request.data") || text.contains("validated_data"))
        && fields.is_empty()
    {
        fields.push(MutationFieldFact {
            field: "*".to_owned(),
            value: "serializer input".to_owned(),
            source_id: Some(format!("source:{}:body", file.relative_path)),
        });
    }
    fields.sort_by(|left, right| left.field.cmp(&right.field));
    fields.dedup_by(|left, right| left.field == right.field && left.source_id == right.source_id);
    fields
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

fn extract_mutation_fields(window: &str, file: &SourceFile) -> Vec<MutationFieldFact> {
    let mut fields = Vec::new();
    let trimmed = window
        .trim()
        .trim_matches(|character| character == '{' || character == '}');
    if matches!(
        trimmed,
        "body" | "req.body" | "request.body" | "request.data"
    ) || window.contains("data: body")
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
    for field in assignment_mutation_fields(window) {
        if !fields.iter().any(|existing| existing.field == field) {
            fields.push(MutationFieldFact {
                field: field.clone(),
                value: format!("body.{field}"),
                source_id: Some(format!("source:{}:body", file.relative_path)),
            });
        }
    }
    fields
}

fn assignment_mutation_fields(window: &str) -> Vec<String> {
    let mut fields = Vec::new();
    for line in window.lines() {
        let trimmed = line.trim();
        if !(trimmed.contains(" = body.") || trimmed.contains(" = request.data")) {
            continue;
        }
        let Some(left) = trimmed.split('=').next().map(str::trim) else {
            continue;
        };
        let Some(field) = left.rsplit('.').next() else {
            continue;
        };
        if !field.is_empty() {
            fields.push(field.to_owned());
        }
    }
    fields.sort();
    fields.dedup();
    fields
}

fn object_section<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let key_index = text.find(key)?;
    let after_key = &text[key_index + key.len()..];
    let colon = after_key.find(':')?;
    let after_colon = after_key[colon + 1..].trim_start();
    let open = after_colon.chars().next()?;
    if open != '{' {
        return Some(after_colon.split(',').next().unwrap_or(after_colon).trim());
    }
    let mut depth = 0usize;
    for (index, character) in after_colon.char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(&after_colon[..=index]);
                }
            }
            _ => {}
        }
    }
    Some(after_colon)
}

fn request_controlled_value(text: &str) -> String {
    for candidate in [
        "req.params",
        "params",
        "invoice_id",
        "client_id",
        "id",
        "request.path_params",
    ] {
        if text.contains(candidate) {
            return candidate.to_owned();
        }
    }
    "request-controlled id".to_owned()
}

fn contains_id_filter(window: &str) -> bool {
    window.contains(" id")
        || window.contains("id:")
        || window.contains(".id")
        || window.contains("_id")
        || window.contains("invoice_id")
        || window.contains("client_id")
}

fn surrounding_window_for_line(text: &str, line: usize, radius: usize) -> String {
    let mut offset = 0;
    for (index, item) in text.lines().enumerate() {
        if index + 1 == line {
            break;
        }
        offset += item.len() + 1;
    }
    surrounding_window_for_offset(text, offset, radius)
}

fn surrounding_window_for_offset(text: &str, offset: usize, radius: usize) -> String {
    let start = previous_char_boundary(text, offset.saturating_sub(radius));
    let end = next_char_boundary(text, offset.saturating_add(radius).min(text.len()));
    text[start..end].to_owned()
}

fn previous_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn next_char_boundary(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
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
    use rulepath_ir::{Language, Position};
    use rulepath_parsers::{CallFact, ParsedFile};

    fn empty_config() -> ResolvedConfig {
        rulepath_config::default_resolved_config()
    }

    #[test]
    fn adapters_are_registered_deterministically() {
        let descriptors = built_in_data_layer_descriptors();
        let names = descriptors
            .iter()
            .map(|descriptor| descriptor.name)
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["prisma", "sqlalchemy", "django_orm"]);
    }

    #[test]
    fn prisma_extraction_uses_parsed_calls() {
        let file = SourceFile {
            path: "src/services/invoices.ts".into(),
            relative_path: "src/services/invoices.ts".to_owned(),
            language: Language::TypeScript,
            text: "return prisma.invoice.update({ where: { id }, data: req.body })".to_owned(),
        };
        let parsed = ParsedFile {
            language: Language::TypeScript,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![CallFact {
                callee: "prisma.invoice.update".to_owned(),
                arguments: vec!["{ where: { id }, data: req.body }".to_owned()],
                span: SourceSpan {
                    file_id: file.relative_path.clone(),
                    start: Position::new(1, 8),
                    end: Position::new(1, 40),
                },
            }],
            suppressions: Vec::new(),
        };

        let operations = extract_prisma_operations(&file, &parsed, &empty_config());
        assert_eq!(operations[0].resource, "Invoice");
        assert_eq!(operations[0].operation, OperationType::Update);
    }

    #[test]
    fn prisma_extraction_handles_alias_nested_where_and_data_without_select_noise() {
        let file = SourceFile {
            path: "src/services/invoices.ts".into(),
            relative_path: "src/services/invoices.ts".to_owned(),
            language: Language::TypeScript,
            text: "const db = new PrismaClient()\nreturn db.invoice.update({ where: { id: req.params.invoiceId, tenantId: req.user.tenantId }, data: { status: req.body.status }, select: { id: true } })".to_owned(),
        };
        let parsed = ParsedFile {
            language: Language::TypeScript,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![CallFact {
                callee: "db.invoice.update".to_owned(),
                arguments: vec![
                    "{ where: { id: req.params.invoiceId, tenantId: req.user.tenantId }, data: { status: req.body.status }, select: { id: true } }".to_owned(),
                ],
                span: SourceSpan::single_line("src/services/invoices.ts", 2),
            }],
            suppressions: Vec::new(),
        };

        let operations = extract_prisma_operations(&file, &parsed, &empty_config());
        assert_eq!(operations[0].method, "prisma.invoice.update");
        assert!(operations[0]
            .filters
            .iter()
            .any(|filter| filter.field == "id" && filter.value == "req.params"));
        assert!(operations[0]
            .filters
            .iter()
            .any(|filter| filter.field == "tenantId"));
        assert_eq!(operations[0].mutation_fields[0].field, "status");
    }

    #[test]
    fn prisma_extraction_marks_bulk_operations() {
        let file = SourceFile {
            path: "src/services/invoices.ts".into(),
            relative_path: "src/services/invoices.ts".to_owned(),
            language: Language::TypeScript,
            text: String::new(),
        };
        let parsed = ParsedFile {
            language: Language::TypeScript,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![
                CallFact {
                    callee: "prisma.invoice.updateMany".to_owned(),
                    arguments: vec!["{ where: { clientId }, data: req.body }".to_owned()],
                    span: SourceSpan::single_line("src/services/invoices.ts", 3),
                },
                CallFact {
                    callee: "prisma.invoice.deleteMany".to_owned(),
                    arguments: vec!["{ where: { clientId } }".to_owned()],
                    span: SourceSpan::single_line("src/services/invoices.ts", 4),
                },
            ],
            suppressions: Vec::new(),
        };

        let operations = extract_prisma_operations(&file, &parsed, &empty_config());
        assert_eq!(operations[0].operation, OperationType::BulkUpdate);
        assert!(operations[0].bulk);
        assert_eq!(operations[1].operation, OperationType::BulkDelete);
        assert!(operations[1].bulk);
    }

    #[test]
    fn sqlalchemy_session_get_and_object_assignment_becomes_update() {
        let file = SourceFile {
            path: "app/invoice_service.py".into(),
            relative_path: "app/invoice_service.py".to_owned(),
            language: Language::Python,
            text: "def update_invoice(invoice_id, body):\n    invoice = session.get(Invoice, invoice_id)\n    invoice.status = body.status\n    session.commit()\n".to_owned(),
        };
        let parsed = ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![CallFact {
                callee: "session.get".to_owned(),
                arguments: vec!["Invoice".to_owned(), "invoice_id".to_owned()],
                span: SourceSpan::single_line("app/invoice_service.py", 2),
            }],
            suppressions: Vec::new(),
        };

        let operations = extract_sqlalchemy_operations(&file, &parsed, &empty_config());
        assert_eq!(operations[0].operation, OperationType::Update);
        assert!(operations[0]
            .filters
            .iter()
            .any(|filter| filter.field == "id" && filter.value == "invoice_id"));
        assert_eq!(operations[0].mutation_fields[0].field, "status");
    }

    #[test]
    fn sqlalchemy_core_bulk_operations_are_marked() {
        let file = SourceFile {
            path: "app/invoice_service.py".into(),
            relative_path: "app/invoice_service.py".to_owned(),
            language: Language::Python,
            text: "session.execute(update(Invoice).where(Invoice.client_id == client_id).values(status=body.status))\nsession.execute(delete(Invoice).where(Invoice.client_id == client_id))".to_owned(),
        };
        let parsed = ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![
                CallFact {
                    callee: "session.execute".to_owned(),
                    arguments: vec![
                        "update(Invoice).where(Invoice.client_id == client_id).values(status=body.status)"
                            .to_owned(),
                    ],
                    span: SourceSpan::single_line("app/invoice_service.py", 1),
                },
                CallFact {
                    callee: "session.execute".to_owned(),
                    arguments: vec!["delete(Invoice).where(Invoice.client_id == client_id)"
                        .to_owned()],
                    span: SourceSpan::single_line("app/invoice_service.py", 2),
                },
            ],
            suppressions: Vec::new(),
        };

        let operations = extract_sqlalchemy_operations(&file, &parsed, &empty_config());
        assert_eq!(operations[0].operation, OperationType::BulkUpdate);
        assert!(operations[0].bulk);
        assert_eq!(operations[1].operation, OperationType::BulkDelete);
        assert!(operations[1].bulk);
    }

    #[test]
    fn django_get_filter_and_tenant_scope_are_extracted() {
        let file = SourceFile {
            path: "app/views.py".into(),
            relative_path: "app/views.py".to_owned(),
            language: Language::Python,
            text: "Invoice.objects.get(id=self.kwargs[\"pk\"])\nInvoice.objects.filter(tenant_id=self.request.user.tenant_id)\n".to_owned(),
        };
        let parsed = ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![
                CallFact {
                    callee: "Invoice.objects.get".to_owned(),
                    arguments: vec!["id=self.kwargs[\"pk\"]".to_owned()],
                    span: SourceSpan::single_line("app/views.py", 1),
                },
                CallFact {
                    callee: "Invoice.objects.filter".to_owned(),
                    arguments: vec!["tenant_id=self.request.user.tenant_id".to_owned()],
                    span: SourceSpan::single_line("app/views.py", 2),
                },
            ],
            suppressions: Vec::new(),
        };

        let operations = extract_django_orm_operations(&file, &parsed, &empty_config());
        assert_eq!(operations[0].operation, OperationType::Read);
        assert!(operations[0]
            .filters
            .iter()
            .any(|filter| filter.field == "id" && filter.source_id.is_some()));
        assert!(operations[1]
            .filters
            .iter()
            .any(|filter| filter.field == "tenant_id" && filter.source_id.is_none()));
    }

    #[test]
    fn django_create_and_queryset_bulk_mutations_are_extracted() {
        let file = SourceFile {
            path: "app/views.py".into(),
            relative_path: "app/views.py".to_owned(),
            language: Language::Python,
            text: "Invoice.objects.create(status=request.data[\"status\"])\nInvoice.objects.filter(client_id=self.kwargs[\"client_id\"]).update(status=request.data[\"status\"])\nInvoice.objects.filter(client_id=self.kwargs[\"client_id\"]).delete()\n".to_owned(),
        };
        let parsed = ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![
                CallFact {
                    callee: "Invoice.objects.create".to_owned(),
                    arguments: vec!["status=request.data[\"status\"]".to_owned()],
                    span: SourceSpan::single_line("app/views.py", 1),
                },
                CallFact {
                    callee: "Invoice.objects.filter(client_id=self.kwargs[\"client_id\"]).update"
                        .to_owned(),
                    arguments: vec!["status=request.data[\"status\"]".to_owned()],
                    span: SourceSpan::single_line("app/views.py", 2),
                },
                CallFact {
                    callee: "Invoice.objects.filter(client_id=self.kwargs[\"client_id\"]).delete"
                        .to_owned(),
                    arguments: Vec::new(),
                    span: SourceSpan::single_line("app/views.py", 3),
                },
            ],
            suppressions: Vec::new(),
        };

        let operations = extract_django_orm_operations(&file, &parsed, &empty_config());
        assert_eq!(operations[0].operation, OperationType::Create);
        assert!(operations[0]
            .mutation_fields
            .iter()
            .any(|field| field.field == "status" && field.source_id.is_some()));
        assert!(operations
            .iter()
            .any(|operation| operation.operation == OperationType::BulkUpdate && operation.bulk));
        assert!(operations
            .iter()
            .any(|operation| operation.operation == OperationType::BulkDelete && operation.bulk));
    }

    #[test]
    fn django_serializer_save_uses_request_body() {
        let file = SourceFile {
            path: "app/views.py".into(),
            relative_path: "app/views.py".to_owned(),
            language: Language::Python,
            text: "serializer = InvoiceSerializer(data=request.data)\nserializer.is_valid()\nserializer.save()\n".to_owned(),
        };
        let parsed = ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![CallFact {
                callee: "serializer.save".to_owned(),
                arguments: Vec::new(),
                span: SourceSpan::single_line("app/views.py", 3),
            }],
            suppressions: Vec::new(),
        };

        let operations = extract_django_orm_operations(&file, &parsed, &empty_config());
        assert_eq!(operations[0].resource, "Invoice");
        assert_eq!(operations[0].operation, OperationType::Create);
        assert!(operations[0]
            .mutation_fields
            .iter()
            .any(|field| field.field == "*" && field.source_id.is_some()));
    }

    #[test]
    fn source_windows_keep_utf8_boundaries() {
        let prefix = "é".repeat(260);
        let text = format!("{prefix}\nInvoice.objects.get(id=self.kwargs[\"pk\"])\n");
        let offset = text
            .find("Invoice.objects.get")
            .expect("fixture should include ORM call");

        let window = surrounding_window_for_offset(&text, offset, 500);

        assert!(window.contains("Invoice.objects.get"));
        assert!(window.is_char_boundary(window.len()));
    }

    #[test]
    fn django_orm_extraction_handles_non_ascii_context() {
        let prefix = "é".repeat(260);
        let file = SourceFile {
            path: "app/views.py".into(),
            relative_path: "app/views.py".to_owned(),
            language: Language::Python,
            text: format!("{prefix}\nInvoice.objects.get(id=self.kwargs[\"pk\"])\n"),
        };
        let parsed = ParsedFile {
            language: Language::Python,
            file_id: file.relative_path.clone(),
            imports: Vec::new(),
            symbols: Vec::new(),
            calls: vec![CallFact {
                callee: "Invoice.objects.get".to_owned(),
                arguments: vec!["id=self.kwargs[\"pk\"]".to_owned()],
                span: SourceSpan::single_line("app/views.py", 2),
            }],
            suppressions: Vec::new(),
        };

        let operations = extract_django_orm_operations(&file, &parsed, &empty_config());

        assert_eq!(operations[0].resource, "Invoice");
        assert_eq!(operations[0].operation, OperationType::Read);
        assert!(operations[0]
            .filters
            .iter()
            .any(|filter| filter.field == "id" && filter.source_id.is_some()));
    }
}
