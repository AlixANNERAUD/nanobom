//! The dependency graph of a project's latest SBOM, and the paths through which the project
//! pulls in a component.
//!
//! A CycloneDX document lists, for each component (by `bom-ref`), the components it depends on
//! directly, and names the project itself in `metadata.component`. [`crate::inventory`] keeps
//! the edges between the components it stores, replaced with them at each upload; the edges
//! from the project have no parent component, and their children are the project's **direct
//! dependencies**. For a vulnerable component, this module finds the direct dependencies that
//! lead to it and the shortest path from each: what a developer upgrades.
//!
//! Generators fill the graph unevenly: some omit it, some omit the project (`cyclonedx-py`
//! describing an environment, Syft describing an image), and edges may go through components
//! without a package URL, which nanobom does not store. A path may be missing, but every link
//! of a path is in the SBOM:
//!
//! - without any edge from the project, nothing is derived (no guessing the roots from the
//!   components nobody depends on: an environment lists direct dependencies that other
//!   packages also require);
//! - an edge to or from a component that is not stored, or naming a `bom-ref` that several
//!   packages share, is dropped rather than bridged or guessed, so a path never skips a
//!   component; the graph is then flagged [`DependencyPaths::partial`];
//! - paths are capped in number ([`MAXIMUM_PATHS`]) and length ([`MAXIMUM_PATH_LENGTH`]); the
//!   graph may have cycles, which the breadth-first search visits once.
//!
//! Paths are between packages, identified by package URL, not between installed copies of
//! them: the copies of one package are stored once with the union of their edges, so with
//! several copies a path may combine links of different ones.

use std::collections::{HashMap, HashSet, VecDeque};

use nanobom_entity::{component_dependencies, components, projects};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, FromQueryResult, JoinType, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait,
    sea_query::{Alias, Expr},
};
use serde::{Deserialize, Serialize};

use crate::{
    access::{Actor, Permission},
    error::Result,
};

/// At most this many paths are shown for a component, one per direct dependency.
pub const MAXIMUM_PATHS: usize = 5;

/// Paths longer than this many components (the direct dependency and the component included)
/// are not followed.
pub const MAXIMUM_PATH_LENGTH: usize = 32;

/// A component of a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentRef {
    pub purl: String,
    /// The package name, with its namespace when it has one.
    pub name: String,
    pub version: Option<String>,
}

/// How the project pulls in a component, per the dependency graph of its latest SBOM.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyPaths {
    /// The shortest path from each direct dependency that leads to the component, from the
    /// direct dependency to the component (both included), shortest first, at most
    /// [`MAXIMUM_PATHS`]. A component that is itself a direct dependency is a path of one.
    /// Empty when the graph does not link the component to the project.
    pub paths: Vec<Vec<ComponentRef>>,
    /// How many more direct dependencies lead to the component than `paths` shows.
    pub more: usize,
    /// Whether the SBOM has links the graph could not keep, through components without a
    /// package URL or `bom-ref`s shared by several packages: other paths may exist.
    pub partial: bool,
}

/// A component's place in a search towards a target component.
#[derive(Debug, Clone, Copy)]
struct Step {
    distance: usize,
    /// The next component towards the target; `None` for the target itself.
    next: Option<i64>,
}

/// The dependency graph of a project, loaded whole: components are identified by their
/// identifier in the `components` table.
#[derive(Debug, Default)]
pub(crate) struct Graph {
    components: HashMap<i64, ComponentRef>,
    by_purl: HashMap<String, i64>,
    /// For each component, the components that depend on it, in display order.
    parents: HashMap<i64, Vec<i64>>,
    direct: HashSet<i64>,
    /// See [`DependencyPaths::partial`].
    partial: bool,
}

/// An edge with its two components, as read by [`Graph::load`].
#[derive(Debug, FromQueryResult)]
struct EdgeRow {
    parent_component_id: Option<i64>,
    child_component_id: i64,
    parent_purl: Option<String>,
    parent_name: Option<String>,
    parent_version: Option<String>,
    child_purl: String,
    child_name: String,
    child_version: Option<String>,
    dependencies_partial: bool,
}

impl Graph {
    /// The graph of a project's latest SBOM, without authorization.
    ///
    /// Edges, their components and the project's flag come from one statement: two reads could
    /// straddle an upload (which replaces the components and their identifiers) and pair the
    /// edges of one SBOM with the components of another, and a transaction would not prevent
    /// it on PostgreSQL, whose default isolation level takes a snapshot per statement. Only the
    /// components that appear in an edge are loaded; the others are in no path anyway.
    pub(crate) async fn load(database: &impl ConnectionTrait, project_id: i64) -> Result<Self> {
        let parent = Alias::new("parent_component");
        let child = Alias::new("child_component");
        let rows = component_dependencies::Entity::find()
            .select_only()
            .column(component_dependencies::Column::ParentComponentId)
            .column(component_dependencies::Column::ChildComponentId)
            .join_as(
                JoinType::LeftJoin,
                component_dependencies::Relation::Components1.def(),
                parent.clone(),
            )
            .join_as(
                JoinType::InnerJoin,
                component_dependencies::Relation::Components2.def(),
                child.clone(),
            )
            .join(
                JoinType::InnerJoin,
                component_dependencies::Relation::Projects.def(),
            )
            .column_as(
                Expr::col((parent.clone(), components::Column::Purl)),
                "parent_purl",
            )
            .column_as(
                Expr::col((parent.clone(), components::Column::Name)),
                "parent_name",
            )
            .column_as(
                Expr::col((parent, components::Column::Version)),
                "parent_version",
            )
            .column_as(
                Expr::col((child.clone(), components::Column::Purl)),
                "child_purl",
            )
            .column_as(
                Expr::col((child.clone(), components::Column::Name)),
                "child_name",
            )
            .column_as(
                Expr::col((child, components::Column::Version)),
                "child_version",
            )
            .column(projects::Column::DependenciesPartial)
            .filter(component_dependencies::Column::ProjectId.eq(project_id))
            .order_by_asc(component_dependencies::Column::Id)
            .into_model::<EdgeRow>()
            .all(database)
            .await?;
        let partial = rows.first().is_some_and(|row| row.dependencies_partial);
        let mut components = HashMap::new();
        let mut edges = Vec::with_capacity(rows.len());
        for row in rows {
            if let (Some(id), Some(purl), Some(name)) =
                (row.parent_component_id, row.parent_purl, row.parent_name)
            {
                components.insert(
                    id,
                    ComponentRef {
                        purl,
                        name,
                        version: row.parent_version,
                    },
                );
            }
            components.insert(
                row.child_component_id,
                ComponentRef {
                    purl: row.child_purl,
                    name: row.child_name,
                    version: row.child_version,
                },
            );
            edges.push((row.parent_component_id, row.child_component_id));
        }
        let mut graph = Self::new(components, &edges);
        graph.partial = partial;
        Ok(graph)
    }

    /// A graph from its components and its edges, a `None` parent being the project. Edges
    /// naming an unknown component are ignored.
    pub(crate) fn new(
        components: HashMap<i64, ComponentRef>,
        edges: &[(Option<i64>, i64)],
    ) -> Self {
        let mut direct = HashSet::new();
        let mut parents: HashMap<i64, Vec<i64>> = HashMap::new();
        for &(parent, child) in edges {
            if !components.contains_key(&child) {
                continue;
            }
            match parent {
                None => {
                    direct.insert(child);
                }
                Some(parent) if parent != child && components.contains_key(&parent) => {
                    parents.entry(child).or_default().push(parent);
                }
                Some(_) => {}
            }
        }
        // Sorted, so that the search, and the paths it picks among equally short ones, do not
        // depend on the order of the rows.
        let order = |id: &i64| {
            let component = &components[id];
            (
                component.name.clone(),
                component.version.clone(),
                component.purl.clone(),
            )
        };
        for list in parents.values_mut() {
            list.sort_by_cached_key(order);
            list.dedup();
        }
        Self {
            by_purl: components
                .iter()
                .map(|(id, component)| (component.purl.clone(), *id))
                .collect(),
            components,
            parents,
            direct,
            partial: false,
        }
    }

    /// Whether the SBOM said which components the project depends on directly.
    pub(crate) fn is_known(&self) -> bool {
        !self.direct.is_empty()
    }

    /// Each component that leads to `target` within [`MAXIMUM_PATH_LENGTH`], with its distance
    /// to it (0 for the target itself) and the next component on a shortest path to it.
    fn search(&self, target: i64) -> HashMap<i64, Step> {
        let mut steps = HashMap::from([(
            target,
            Step {
                distance: 0,
                next: None,
            },
        )]);
        let mut queue = VecDeque::from([target]);
        while let Some(current) = queue.pop_front() {
            let distance = steps[&current].distance;
            if distance + 1 >= MAXIMUM_PATH_LENGTH {
                continue;
            }
            for parent in self.parents.get(&current).into_iter().flatten() {
                if !steps.contains_key(parent) {
                    steps.insert(
                        *parent,
                        Step {
                            distance: distance + 1,
                            next: Some(current),
                        },
                    );
                    queue.push_back(*parent);
                }
            }
        }
        steps
    }

    /// The direct dependencies that lead to `target`, nearest first, then by name.
    fn leading(&self, steps: &HashMap<i64, Step>) -> Vec<i64> {
        let mut leading: Vec<i64> = self
            .direct
            .iter()
            .copied()
            .filter(|id| steps.contains_key(id))
            .collect();
        leading.sort_by_cached_key(|id| {
            let component = &self.components[id];
            (
                steps[id].distance,
                component.name.clone(),
                component.version.clone(),
                component.purl.clone(),
            )
        });
        leading
    }

    /// The direct dependencies that lead to the component with this package URL (itself when
    /// it is one), sorted by name; empty when the graph does not link it to the project.
    pub(crate) fn introduced_via(&self, purl: &str) -> Vec<ComponentRef> {
        let Some(&target) = self.by_purl.get(purl).filter(|_| self.is_known()) else {
            return Vec::new();
        };
        let steps = self.search(target);
        let mut leading: Vec<ComponentRef> = self
            .leading(&steps)
            .into_iter()
            .map(|id| self.components[&id].clone())
            .collect();
        leading.sort_by(|left, right| {
            (&left.name, &left.version, &left.purl).cmp(&(&right.name, &right.version, &right.purl))
        });
        leading
    }

    /// The paths to the component with this package URL, or `None` when the SBOM did not
    /// describe the project's direct dependencies.
    pub(crate) fn paths(&self, purl: &str) -> Option<DependencyPaths> {
        if !self.is_known() {
            return None;
        }
        let Some(&target) = self.by_purl.get(purl) else {
            return Some(DependencyPaths {
                partial: self.partial,
                ..DependencyPaths::default()
            });
        };
        let steps = self.search(target);
        let leading = self.leading(&steps);
        let paths = leading
            .iter()
            .take(MAXIMUM_PATHS)
            .map(|&start| {
                let mut path = vec![self.components[&start].clone()];
                let mut current = start;
                while let Some(next) = steps[&current].next {
                    path.push(self.components[&next].clone());
                    current = next;
                }
                path
            })
            .collect();
        Some(DependencyPaths {
            paths,
            more: leading.len().saturating_sub(MAXIMUM_PATHS),
            partial: self.partial,
        })
    }
}

/// How the project pulls in the component with this package URL, per its latest SBOM: `None`
/// when the SBOM did not say which components the project depends on directly. Requires
/// [`Permission::View`].
pub async fn paths(
    database: &impl ConnectionTrait,
    actor: &Actor,
    project_id: i64,
    purl: &str,
) -> Result<Option<DependencyPaths>> {
    crate::projects::authorize(database, actor, project_id, Permission::View).await?;
    Ok(Graph::load(database, project_id).await?.paths(purl))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A graph of components named after their identifier (`c1`, `c2`…), version 1.
    fn graph(count: i64, edges: &[(Option<i64>, i64)]) -> Graph {
        let components = (1..=count)
            .map(|id| {
                (
                    id,
                    ComponentRef {
                        purl: format!("pkg:npm/c{id}@1"),
                        name: format!("c{id}"),
                        version: Some("1".to_owned()),
                    },
                )
            })
            .collect();
        Graph::new(components, edges)
    }

    fn names(paths: &DependencyPaths) -> Vec<Vec<String>> {
        paths
            .paths
            .iter()
            .map(|path| {
                path.iter()
                    .map(|component| component.name.clone())
                    .collect()
            })
            .collect()
    }

    #[test]
    fn a_diamond_gives_one_shortest_path_per_direct_dependency() {
        // project -> c1, c2; c1 -> c3 -> c5; c1 -> c4 -> c5; c2 -> c5.
        let graph = graph(
            5,
            &[
                (None, 1),
                (None, 2),
                (Some(1), 3),
                (Some(1), 4),
                (Some(3), 5),
                (Some(4), 5),
                (Some(2), 5),
            ],
        );
        let paths = graph.paths("pkg:npm/c5@1").unwrap();
        assert_eq!(names(&paths), [vec!["c2", "c5"], vec!["c1", "c3", "c5"]]);
        assert_eq!(paths.more, 0);
        let via: Vec<_> = graph
            .introduced_via("pkg:npm/c5@1")
            .into_iter()
            .map(|component| component.name)
            .collect();
        assert_eq!(via, ["c1", "c2"]);
    }

    #[test]
    fn a_direct_dependency_is_a_path_of_its_own() {
        // project -> c1, c2; c2 -> c1.
        let graph = graph(2, &[(None, 1), (None, 2), (Some(2), 1)]);
        let paths = graph.paths("pkg:npm/c1@1").unwrap();
        assert_eq!(names(&paths), [vec!["c1"], vec!["c2", "c1"]]);
    }

    #[test]
    fn cycles_are_visited_once() {
        // project -> c1 -> c2 -> c3 -> c2, c3 -> c4.
        let graph = graph(
            4,
            &[
                (None, 1),
                (Some(1), 2),
                (Some(2), 3),
                (Some(3), 2),
                (Some(3), 4),
            ],
        );
        let paths = graph.paths("pkg:npm/c4@1").unwrap();
        assert_eq!(names(&paths), [vec!["c1", "c2", "c3", "c4"]]);
        // A cycle that never reaches the project leads nowhere.
        let graph = graph_with_island();
        assert_eq!(
            graph.paths("pkg:npm/c3@1").unwrap(),
            DependencyPaths::default()
        );
        assert!(graph.introduced_via("pkg:npm/c3@1").is_empty());
    }

    fn graph_with_island() -> Graph {
        // project -> c1; c2 <-> c3, unreachable from the project.
        graph(3, &[(None, 1), (Some(2), 3), (Some(3), 2)])
    }

    #[test]
    fn paths_are_capped_in_number_and_length() {
        // project -> c1..c7, each -> c8.
        let mut edges: Vec<_> = (1..=7).flat_map(|id| [(None, id), (Some(id), 8)]).collect();
        let wide = graph(8, &edges);
        let paths = wide.paths("pkg:npm/c8@1").unwrap();
        assert_eq!(paths.paths.len(), MAXIMUM_PATHS);
        assert_eq!(paths.more, 2);
        assert_eq!(wide.introduced_via("pkg:npm/c8@1").len(), 7);

        // A chain one component longer than the maximum: project -> c1 -> ... -> c33.
        let length = i64::try_from(MAXIMUM_PATH_LENGTH).unwrap() + 1;
        edges = vec![(None, 1)];
        edges.extend((1..length).map(|id| (Some(id), id + 1)));
        let chain = graph(length, &edges);
        let last = format!("pkg:npm/c{length}@1");
        assert_eq!(chain.paths(&last).unwrap(), DependencyPaths::default());
        let previous = format!("pkg:npm/c{}@1", length - 1);
        assert_eq!(
            chain.paths(&previous).unwrap().paths[0].len(),
            MAXIMUM_PATH_LENGTH
        );
    }

    #[test]
    fn without_edges_from_the_project_nothing_is_known() {
        let graph = graph(2, &[(Some(1), 2)]);
        assert!(!graph.is_known());
        assert_eq!(graph.paths("pkg:npm/c2@1"), None);
        assert!(graph.introduced_via("pkg:npm/c2@1").is_empty());
    }

    #[test]
    fn a_component_outside_the_graph_has_no_path() {
        let graph = graph(1, &[(None, 1)]);
        assert_eq!(
            graph.paths("pkg:npm/missing@1").unwrap(),
            DependencyPaths::default()
        );
    }
}
