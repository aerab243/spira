// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: PackageSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageSource {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
}
