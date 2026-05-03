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
            DataLayer::DjangoOrm => extract_django_orm_operations(file, config),
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
    for call in &parsed.calls {
        let Some(rest) = call.callee.strip_prefix("prisma.") else {
            continue;
        };
        let mut parts = rest.split('.');
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
            filters: extract_filters(&resource, &window, config, file),
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

fn extract_sqlalchemy_operations(
    file: &SourceFile,
    parsed: &ParsedFile,
    config: &ResolvedConfig,
) -> Vec<OperationFact> {
    let mut operations = Vec::new();
    for call in &parsed.calls {
        let marker = call.callee.as_str();
        if !matches!(marker, "session.get" | "select" | "update" | "delete") {
            continue;
        }
        let Some(resource) = call
            .arguments
            .first()
            .map(|argument| argument.trim())
            .filter(|argument| !argument.is_empty())
        else {
            continue;
        };
        let window = surrounding_window_for_line(&file.text, call.span.start.line, 500);
        let operation = if marker == "delete" {
            OperationType::Delete
        } else if marker == "update"
            || window.contains("session.commit")
            || window.contains("body.status")
        {
            OperationType::Update
        } else {
            OperationType::Read
        };
        operations.push(OperationFact {
            id: format!(
                "sink:sqlalchemy.{resource}.{marker}:{}:{}",
                file.relative_path, call.span.start.line
            ),
            data_layer: DataLayer::SqlAlchemy,
            resource: resource.to_owned(),
            operation,
            method: marker.to_owned(),
            filters: extract_filters(resource, &window, config, file),
            mutation_fields: extract_mutation_fields(&window, file),
            bulk: marker == "update" || marker == "delete",
            span: call.span.clone(),
        });
    }
    operations
}

fn extract_django_orm_operations(file: &SourceFile, config: &ResolvedConfig) -> Vec<OperationFact> {
    let mut operations = Vec::new();
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
    operations
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
    let start = offset.saturating_sub(radius);
    let end = (offset + radius).min(text.len());
    text[start..end].to_owned()
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
}
