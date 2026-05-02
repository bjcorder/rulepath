use rulepath_ir::Framework;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameworkDescriptor {
    pub id: Framework,
    pub name: &'static str,
}

#[must_use]
pub fn built_in_frameworks() -> &'static [FrameworkDescriptor] {
    &[
        FrameworkDescriptor {
            id: Framework::Express,
            name: "express",
        },
        FrameworkDescriptor {
            id: Framework::FastApi,
            name: "fastapi",
        },
        FrameworkDescriptor {
            id: Framework::Django,
            name: "django",
        },
        FrameworkDescriptor {
            id: Framework::DjangoRestFramework,
            name: "django_rest_framework",
        },
        FrameworkDescriptor {
            id: Framework::NextJs,
            name: "nextjs",
        },
    ]
}
