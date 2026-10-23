import re
from typing import Literal

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from semantic_version import Version as Semver


def normalize(ecosystem: str, name: str) -> tuple[str, str]:
    if ecosystem.lower() in {"pip", "pypi", "python"}:
        eco, name = "PyPI", re.sub(r"[-_.]+", "-", name).lower()
        pattern = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    elif ecosystem.lower() == "npm":
        eco, name = "npm", name.lower()
        pattern = r"(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*"
    else:
        raise ValueError("Only npm and PyPI are supported")
    if not re.fullmatch(pattern, name) or len(name) > 214:
        raise ValueError("Invalid package name")
    return eco, name


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Package(StrictModel):
    ecosystem: str
    name: str
    version: str = Field(min_length=1, max_length=128)
    locator: str = Field(default="", max_length=1024)
    direct: bool = False
    dependencies: list[str] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def exact(self):
        self.ecosystem, self.name = normalize(self.ecosystem, self.name)
        try:
            Version(self.version) if self.ecosystem == "PyPI" else Semver(self.version)
        except (InvalidVersion, ValueError) as exc:
            raise ValueError("An exact installed version is required") from exc
        return self


class SBOM(StrictModel):
    source: str = Field(min_length=1, max_length=300)
    packages: list[Package] = Field(min_length=1, max_length=10000)
    graph_complete: bool = False
    warnings: list[str] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def unique(self):
        keys = [p.locator or f"{p.ecosystem}:{p.name}@{p.version}" for p in self.packages]
        if len(keys) != len(set(keys)):
            raise ValueError("Package locators must be unique")
        locators = set(keys)
        if any(dep not in locators for p in self.packages for dep in p.dependencies):
            raise ValueError("Dependency edges must reference SBOM locators")
        return self


class ResponseRequest(StrictModel):
    ecosystem: str
    package: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=128)
    ai_brief: bool = False

    @model_validator(mode="after")
    def validate_package(self):
        p = Package(ecosystem=self.ecosystem, name=self.package, version=self.version)
        self.ecosystem, self.package = p.ecosystem, p.name
        return self


class Finding(StrictModel):
    indicator: str = Field(min_length=1, max_length=300)
    kind: Literal["ip", "domain"]
    count: int = Field(ge=1)
    source: str = Field(max_length=200)


class ScanReport(StrictModel):
    findings: list[Finding] = Field(default_factory=list, max_length=1000)
    summary: str = Field(default="", max_length=2000)


class Proposal(StrictModel):
    emergency_id: str
    target_version: str = Field(min_length=1, max_length=128)
    pr_url: str = Field(max_length=1000)
    test_command: list[str] = Field(min_length=1, max_length=100)
    test_passed: bool
    rollback_plan: str = Field(min_length=10, max_length=4000)

    @field_validator("pr_url")
    @classmethod
    def valid_pr(cls, value):
        if not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+/pull/\d+", value):
            raise ValueError("A GitHub pull request URL is required")
        return value


class Review(StrictModel):
    decision: Literal["APPROVED", "REJECTED"]
    reason: str = Field(min_length=3, max_length=2000)
    revision: str
