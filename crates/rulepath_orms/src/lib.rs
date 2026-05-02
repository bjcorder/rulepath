use rulepath_ir::DataLayer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataLayerDescriptor {
    pub id: DataLayer,
    pub name: &'static str,
}

#[must_use]
pub fn built_in_data_layers() -> &'static [DataLayerDescriptor] {
    &[
        DataLayerDescriptor {
            id: DataLayer::Prisma,
            name: "prisma",
        },
        DataLayerDescriptor {
            id: DataLayer::SqlAlchemy,
            name: "sqlalchemy",
        },
        DataLayerDescriptor {
            id: DataLayer::DjangoOrm,
            name: "django_orm",
        },
    ]
}
