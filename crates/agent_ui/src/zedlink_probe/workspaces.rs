use std::collections::BTreeMap;

use futures::StreamExt as _;
use gpui::{AnyWindowHandle, TaskExt as _, WindowHandle};
use remote::{RemoteConnectionOptions, SshConnectionOptions};
use workspace::{MultiWorkspace, OpenMode, PathList, ProjectGroupKey, Workspace};

use super::*;
use crate::thread_metadata_store::{ThreadMetadata, ThreadMetadataStore};

const MAX_THREADS_PER_PROJECT: usize = 50;
const MIN_THREADS_PER_PROJECT: usize = 5;
// Keeps `workspace.list` well below the gateway's response limit.
const THREAD_BUDGET: usize = 3000;
const MAX_DIRECTORY_ENTRIES: usize = 2000;

#[derive(Default)]
pub(super) struct WorkspaceState {
    opening: RefCell<HashSet<String>>,
    open_errors: RefCell<HashMap<String, String>>,
    pending_thread_exposures: RefCell<HashSet<String>>,
    added_hosts: RefCell<Vec<SshConnectionOptions>>,
    browse_projects: RefCell<HashMap<String, BrowseConnection>>,
    directories: RefCell<HashMap<(String, String), DirectoryRecord>>,
}

enum BrowseConnection {
    Connecting,
    Ready(Entity<project::Project>),
    Failed,
}

enum DirectoryRecord {
    Loading,
    Ready { path: String, entries: Vec<Value> },
    Failed,
}

struct HostRecord {
    id: String,
    options: Option<RemoteConnectionOptions>,
    projects: BTreeMap<Vec<PathBuf>, ProjectRecord>,
}

#[derive(Default)]
struct ProjectRecord {
    open: bool,
    threads: Vec<ThreadMetadata>,
}

pub(super) fn host_id(options: Option<&RemoteConnectionOptions>) -> String {
    match options {
        None => "local".to_string(),
        Some(RemoteConnectionOptions::Ssh(options)) => {
            format!("ssh:{}", options.connection_string())
        }
        Some(RemoteConnectionOptions::Wsl(options)) => format!("wsl:{}", options.distro_name),
        Some(RemoteConnectionOptions::Docker(options)) => format!("docker:{}", options.name),
        #[cfg(any(test, feature = "test-support"))]
        Some(RemoteConnectionOptions::Mock(options)) => format!("mock:{}", options.id),
    }
}

fn project_id(host_id: &str, paths: &[PathBuf]) -> String {
    let paths = paths
        .iter()
        .map(|path| path.to_string_lossy())
        .collect::<Vec<_>>()
        .join("\n");
    format!("{host_id}\n{paths}")
}

fn multi_workspace_windows(cx: &App) -> Vec<WindowHandle<MultiWorkspace>> {
    cx.windows()
        .into_iter()
        .filter_map(|window: AnyWindowHandle| window.downcast::<MultiWorkspace>())
        .collect()
}

fn open_workspaces(cx: &App) -> Vec<Entity<Workspace>> {
    multi_workspace_windows(cx)
        .into_iter()
        .filter_map(|window| window.read(cx).ok())
        .flat_map(|multi_workspace| multi_workspace.workspaces().cloned().collect::<Vec<_>>())
        .collect()
}

fn collect_hosts(state: &WorkspaceState, cx: &App) -> Vec<HostRecord> {
    let mut hosts: Vec<HostRecord> = vec![HostRecord {
        id: host_id(None),
        options: None,
        projects: BTreeMap::new(),
    }];
    fn host_entry<'a>(
        hosts: &'a mut Vec<HostRecord>,
        options: Option<&RemoteConnectionOptions>,
    ) -> &'a mut HostRecord {
        let id = host_id(options);
        let index = match hosts.iter().position(|host| host.id == id) {
            Some(index) => index,
            None => {
                hosts.push(HostRecord {
                    id,
                    options: options.cloned(),
                    projects: BTreeMap::new(),
                });
                hosts.len() - 1
            }
        };
        &mut hosts[index]
    }

    let saved_connections = cx
        .global::<SettingsStore>()
        .merged_settings()
        .remote
        .ssh_connections
        .clone()
        .unwrap_or_default();
    for connection in saved_connections {
        let projects = connection.projects.clone();
        let options = RemoteConnectionOptions::Ssh(SshConnectionOptions::from(connection));
        let host = host_entry(&mut hosts, Some(&options));
        for project in projects {
            let paths = PathList::new(&project.paths).paths().to_vec();
            if !paths.is_empty() {
                host.projects.entry(paths).or_default();
            }
        }
    }
    for options in state.added_hosts.borrow().iter() {
        host_entry(
            &mut hosts,
            Some(&RemoteConnectionOptions::Ssh(options.clone())),
        );
    }

    for window in multi_workspace_windows(cx) {
        let Ok(multi_workspace) = window.read(cx) else {
            continue;
        };
        for key in multi_workspace.project_group_keys() {
            let paths = key.path_list().paths().to_vec();
            if !paths.is_empty() {
                host_entry(&mut hosts, key.host())
                    .projects
                    .entry(paths)
                    .or_default();
            }
        }
        for workspace in multi_workspace.workspaces() {
            let key = workspace.read(cx).project().read(cx).project_group_key(cx);
            let paths = key.path_list().paths().to_vec();
            if !paths.is_empty() {
                host_entry(&mut hosts, key.host())
                    .projects
                    .entry(paths)
                    .or_default()
                    .open = true;
            }
        }
    }

    if let Some(store) = ThreadMetadataStore::try_global(cx) {
        for metadata in store.read(cx).entries() {
            if metadata.archived || metadata.session_id.is_none() {
                continue;
            }
            let paths = metadata.main_worktree_paths().paths().to_vec();
            if paths.is_empty() {
                continue;
            }
            host_entry(&mut hosts, metadata.remote_connection.as_ref())
                .projects
                .entry(paths)
                .or_default()
                .threads
                .push(metadata.clone());
        }
    }
    hosts
}

fn host_value(
    host: &HostRecord,
    state: &WorkspaceState,
    loaded: &HashSet<String>,
    thread_limit: usize,
    cx: &App,
) -> Value {
    let (kind, label, detail, connected) = match &host.options {
        None => ("local", "This computer".to_string(), None, true),
        Some(options) => {
            let kind = match options {
                RemoteConnectionOptions::Ssh(_) => "ssh",
                RemoteConnectionOptions::Wsl(_) => "wsl",
                _ => "container",
            };
            let detail = match options {
                RemoteConnectionOptions::Ssh(ssh) => Some(ssh.connection_string()),
                _ => None,
            };
            (
                kind,
                options.display_name(),
                detail,
                remote::has_active_connection(options, cx),
            )
        }
    };
    let mut projects = host
        .projects
        .iter()
        .map(|(paths, project)| {
            let id = project_id(&host.id, paths);
            let mut threads = project.threads.iter().collect::<Vec<_>>();
            threads.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
            let updated_at = threads.first().map(|thread| thread.updated_at);
            let threads = threads
                .into_iter()
                .take(thread_limit)
                .filter_map(|thread| {
                    let session_id = thread.session_id.as_ref()?.to_string();
                    Some(json!({
                        "thread_id": session_id,
                        "title": thread.title().map(|title| title.to_string()),
                        "agent": thread.agent_id.to_string(),
                        "updated_at": thread.updated_at.to_rfc3339(),
                        "loaded": loaded.contains(&session_id),
                    }))
                })
                .collect::<Vec<_>>();
            let name = paths
                .iter()
                .map(|path| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.to_string_lossy().into_owned())
                })
                .collect::<Vec<_>>()
                .join(", ");
            let value = json!({
                "project_id": id,
                "host_id": host.id,
                "paths": paths.iter().map(|path| path.to_string_lossy()).collect::<Vec<_>>(),
                "name": name,
                "open": project.open,
                "opening": state.opening.borrow().contains(&id),
                "error": state.open_errors.borrow().get(&id),
                "threads": threads,
            });
            (project.open, updated_at, value)
        })
        .collect::<Vec<_>>();
    projects.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| right.0.cmp(&left.0)));
    json!({
        "host_id": host.id,
        "kind": kind,
        "label": label,
        "detail": detail,
        "connected": connected,
        "projects": projects.into_iter().map(|(_, _, value)| value).collect::<Vec<_>>(),
    })
}

fn probe_state(cx: &App) -> Option<Rc<ProbeState>> {
    cx.try_global::<ProbeGlobal>()
        .map(|global| global.0.clone())
}

pub(super) fn workspace_list(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    if !matches_instance(request, state) {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    let loaded = loaded_thread_views(None, cx)
        .into_iter()
        .map(|(thread, _)| thread.read(cx).session_id().to_string())
        .collect::<HashSet<_>>();
    let hosts = collect_hosts(&state.workspaces, cx);
    let project_count = hosts.iter().map(|host| host.projects.len()).sum::<usize>();
    let thread_limit = (THREAD_BUDGET / project_count.max(1))
        .clamp(MIN_THREADS_PER_PROJECT, MAX_THREADS_PER_PROJECT);
    let hosts = hosts
        .iter()
        .map(|host| host_value(host, &state.workspaces, &loaded, thread_limit, cx))
        .collect::<Vec<_>>();
    success(&request.request_id, json!({ "hosts": hosts }))
}

fn requested_paths(request: &ProbeRequest) -> Option<Vec<PathBuf>> {
    let paths = request
        .params
        .get("paths")?
        .as_array()?
        .iter()
        .map(|path| {
            path.as_str()
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
        })
        .collect::<Option<Vec<_>>>()?;
    (!paths.is_empty() && paths.len() <= 16 && paths.iter().all(|path| path.is_absolute()))
        .then_some(paths)
}

fn host_options(
    state: &WorkspaceState,
    host_id: &str,
    cx: &App,
) -> Option<Option<RemoteConnectionOptions>> {
    collect_hosts(state, cx)
        .into_iter()
        .find(|host| host.id == host_id)
        .map(|host| host.options)
}

pub(super) fn workspace_open(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    if !matches_instance(request, state) {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !params_contain_only(
        &request.params,
        &["instance_id", "epoch", "host_id", "paths"],
    ) {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let (Some(host_id), Some(paths)) = (
        request.params.get("host_id").and_then(Value::as_str),
        requested_paths(request),
    ) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let Some(options) = host_options(&state.workspaces, host_id, cx) else {
        return error(&request.request_id, "HOST_UNAVAILABLE");
    };
    let path_list = PathList::new(&paths);
    let id = project_id(host_id, path_list.paths());
    let already_open = open_workspaces(cx).iter().any(|workspace| {
        let key = workspace.read(cx).project().read(cx).project_group_key(cx);
        key.path_list() == &path_list && host_id_matches(key.host(), host_id)
    });
    if already_open {
        return success(&request.request_id, json!({ "outcome": "open" }));
    }
    if !state.workspaces.opening.borrow().contains(&id) {
        if let Err(code) = open_workspace(id, path_list, options, None, cx) {
            return error(&request.request_id, code);
        }
    }
    success(&request.request_id, json!({ "outcome": "opening" }))
}

fn host_id_matches(options: Option<&RemoteConnectionOptions>, host_id: &str) -> bool {
    self::host_id(options) == host_id
}

/// Opens (or finds) a workspace the way Zed's sidebar does, including the SSH
/// connection modal on the desktop, then optionally loads a thread into it.
fn open_workspace(
    project_id: String,
    paths: PathList,
    host: Option<RemoteConnectionOptions>,
    thread: Option<ThreadMetadata>,
    cx: &mut App,
) -> Result<(), &'static str> {
    let Some(state) = probe_state(cx) else {
        return Err("INSTANCE_UNAVAILABLE");
    };
    let window = multi_workspace_windows(cx)
        .into_iter()
        .find(|window| {
            window.read(cx).is_ok_and(|multi_workspace| {
                multi_workspace
                    .project_group_keys()
                    .iter()
                    .any(|key| key.path_list() == &paths && key.host() == host.as_ref())
            })
        })
        .or_else(|| {
            cx.active_window()
                .and_then(|window| window.downcast::<MultiWorkspace>())
        })
        .or_else(|| multi_workspace_windows(cx).into_iter().next())
        .ok_or("WORKSPACE_UNAVAILABLE")?;

    state
        .workspaces
        .opening
        .borrow_mut()
        .insert(project_id.clone());
    state
        .workspaces
        .open_errors
        .borrow_mut()
        .remove(&project_id);
    let cleanup = (state.clone(), project_id.clone());
    let provisional_key = ProjectGroupKey::new(host.clone(), paths.clone());
    let result = window.update(cx, |multi_workspace, window, cx| {
        let modal_workspace = multi_workspace.workspace().clone();
        let open_task = multi_workspace.find_or_create_workspace(
            paths,
            host,
            Some(provisional_key),
            {
                let modal_workspace = modal_workspace.clone();
                move |options, window, cx| {
                    remote_connection::connect_with_modal(&modal_workspace, options, window, cx)
                }
            },
            None,
            OpenMode::Add,
            None,
            window,
            cx,
        );
        cx.spawn_in(window, async move |_, cx| {
            let result = open_task.await;
            remote_connection::dismiss_connection_modal(&modal_workspace, cx);
            state.workspaces.opening.borrow_mut().remove(&project_id);
            let workspace = match result {
                Ok(workspace) => workspace,
                Err(open_error) => {
                    state.workspaces.open_errors.borrow_mut().insert(
                        project_id,
                        format!("{open_error:#}").chars().take(512).collect(),
                    );
                    return Err(open_error);
                }
            };
            if let Some(thread) = thread {
                cx.update(|window, cx| load_thread_in_workspace(&workspace, thread, window, cx))?;
            }
            anyhow::Ok(())
        })
        .detach_and_log_err(cx);
    });
    if result.is_err() {
        let (state, project_id) = cleanup;
        state.workspaces.opening.borrow_mut().remove(&project_id);
        return Err("WORKSPACE_UNAVAILABLE");
    }
    Ok(())
}

fn load_thread_in_workspace(
    workspace: &Entity<Workspace>,
    metadata: ThreadMetadata,
    window: &mut gpui::Window,
    cx: &mut App,
) {
    let load = move |panel: Entity<AgentPanel>, window: &mut gpui::Window, cx: &mut App| {
        panel.update(cx, |panel, cx| {
            panel.load_agent_thread(
                Agent::from(metadata.agent_id.clone()),
                metadata.thread_id,
                Some(metadata.folder_paths().clone()),
                metadata.title(),
                false,
                AgentThreadSource::Sidebar,
                window,
                cx,
            );
        });
    };
    if let Some(panel) = workspace.read(cx).panel::<AgentPanel>(cx) {
        load(panel, window, cx);
        return;
    }
    let weak_workspace = workspace.downgrade();
    let mut async_window_cx = window.to_async(cx);
    cx.spawn(async move |_| {
        let panel = AgentPanel::load(weak_workspace.clone(), async_window_cx.clone()).await?;
        weak_workspace.update_in(&mut async_window_cx, |workspace, window, cx| {
            let panel = workspace.panel::<AgentPanel>(cx).unwrap_or_else(|| {
                workspace.add_panel(panel.clone(), window, cx);
                panel
            });
            load(panel, window, cx);
        })?;
        anyhow::Ok(())
    })
    .detach_and_log_err(cx);
}

pub(super) fn thread_open(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    if !matches_instance(request, state) {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !params_contain_only(&request.params, &["instance_id", "epoch", "thread_id"]) {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let Some(session_id) = request
        .params
        .get("thread_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let loaded = loaded_thread_views(None, cx)
        .into_iter()
        .any(|(thread, _)| thread.read(cx).session_id().to_string() == session_id);
    state
        .workspaces
        .pending_thread_exposures
        .borrow_mut()
        .insert(session_id.to_string());
    if loaded {
        return success(&request.request_id, json!({ "outcome": "loaded" }));
    }
    let Some(metadata) = ThreadMetadataStore::try_global(cx).and_then(|store| {
        store
            .read(cx)
            .entry_by_session(&acp::SessionId::new(session_id.to_string()))
            .cloned()
    }) else {
        state
            .workspaces
            .pending_thread_exposures
            .borrow_mut()
            .remove(session_id);
        return error(&request.request_id, "THREAD_NOT_FOUND");
    };

    let host = metadata.remote_connection.clone();
    let folder_paths = metadata.folder_paths().clone();
    let existing = open_workspaces(cx).into_iter().find(|workspace| {
        let workspace = workspace.read(cx);
        workspace.project().read(cx).remote_connection_options(cx) == host.as_ref()
            && PathList::new(&workspace.root_paths(cx)) == folder_paths
    });
    if let Some(workspace) = existing {
        let window = multi_workspace_windows(cx).into_iter().find(|window| {
            window.read(cx).is_ok_and(|multi_workspace| {
                multi_workspace
                    .workspaces()
                    .any(|candidate| candidate == &workspace)
            })
        });
        let Some(window) = window else {
            return error(&request.request_id, "WORKSPACE_UNAVAILABLE");
        };
        if window
            .update(cx, |_, window, cx| {
                load_thread_in_workspace(&workspace, metadata, window, cx)
            })
            .is_err()
        {
            return error(&request.request_id, "WORKSPACE_UNAVAILABLE");
        }
        return success(&request.request_id, json!({ "outcome": "loading" }));
    }

    let id = project_id(&host_id(host.as_ref()), folder_paths.paths());
    if let Err(code) = open_workspace(id, folder_paths, host, Some(metadata), cx) {
        return error(&request.request_id, code);
    }
    success(&request.request_id, json!({ "outcome": "loading" }))
}

/// Exposes threads that a client asked to open once Zed has loaded them.
pub(super) fn expose_requested_threads(state: &Rc<ProbeState>, cx: &mut App) {
    if state
        .workspaces
        .pending_thread_exposures
        .borrow()
        .is_empty()
    {
        return;
    }
    for (thread, _) in loaded_thread_views(None, cx) {
        let id = thread.read(cx).session_id().to_string();
        if state
            .workspaces
            .pending_thread_exposures
            .borrow_mut()
            .remove(&id)
        {
            expose_thread(state, &thread, cx);
        }
    }
}

pub(super) fn host_add(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    if !matches_instance(request, state) {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !params_contain_only(&request.params, &["instance_id", "epoch", "command"]) {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let Some(command) = request
        .params
        .get("command")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|command| !command.is_empty() && command.len() <= 1024)
    else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let Ok(options) = SshConnectionOptions::parse_command_line(command) else {
        return error(&request.request_id, "INVALID_COMMAND");
    };
    // A paired device may only name a destination. Options such as
    // `-o ProxyCommand=...` would let it run arbitrary commands on this computer.
    let has_options = options.args.as_ref().is_some_and(|args| !args.is_empty())
        || options.port_forwards.is_some();
    let safe_destination = [Some(options.host.to_string()), options.username.clone()]
        .into_iter()
        .flatten()
        .all(|value| is_safe_destination_part(&value));
    if has_options || !safe_destination {
        return error(&request.request_id, "INVALID_COMMAND");
    }
    let options_value = RemoteConnectionOptions::Ssh(options.clone());
    let id = host_id(Some(&options_value));
    let known = collect_hosts(&state.workspaces, cx)
        .iter()
        .any(|host| host.id == id);
    if !known {
        state
            .workspaces
            .added_hosts
            .borrow_mut()
            .push(options.clone());
        let fs = workspace::AppState::global(cx).fs.clone();
        settings::update_settings_file(fs, cx, move |settings, _| {
            settings
                .remote
                .ssh_connections
                .get_or_insert_with(Default::default)
                .push(settings::SshConnection {
                    host: options.host.to_string(),
                    username: options.username,
                    port: options.port,
                    args: options.args.unwrap_or_default(),
                    projects: Default::default(),
                    nickname: None,
                    upload_binary_over_ssh: None,
                    port_forwards: options.port_forwards,
                    connection_timeout: options.connection_timeout,
                });
        });
    }
    success(&request.request_id, json!({ "host_id": id }))
}

fn is_safe_destination_part(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_alphanumeric() || "._-:%".contains(character))
}

pub(super) fn host_directory(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    if !matches_instance(request, state) {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !params_contain_only(
        &request.params,
        &["instance_id", "epoch", "host_id", "path"],
    ) {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let (Some(host_id), Some(path)) = (
        request.params.get("host_id").and_then(Value::as_str),
        request
            .params
            .get("path")
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty() && path.len() <= 4096),
    ) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    if !(path == "~" || path.starts_with("~/") || Path::new(path).is_absolute()) {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let key = (host_id.to_string(), path.to_string());
    let record = state.workspaces.directories.borrow_mut().remove(&key);
    match record {
        Some(DirectoryRecord::Ready { path, entries }) => {
            return success(
                &request.request_id,
                json!({ "state": "ready", "path": path, "entries": entries }),
            );
        }
        Some(DirectoryRecord::Failed) => {
            return error(&request.request_id, "DIRECTORY_UNAVAILABLE");
        }
        Some(DirectoryRecord::Loading) => {
            state
                .workspaces
                .directories
                .borrow_mut()
                .insert(key, DirectoryRecord::Loading);
            return success(&request.request_id, json!({ "state": "loading" }));
        }
        None => {}
    }
    let Some(options) = host_options(&state.workspaces, host_id, cx) else {
        return error(&request.request_id, "HOST_UNAVAILABLE");
    };
    let Some(state) = probe_state(cx) else {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    };

    let Some(options) = options else {
        let fs = workspace::AppState::global(cx).fs.clone();
        let expanded = match path.strip_prefix('~') {
            Some(rest) => util::paths::home_dir().join(rest.trim_start_matches('/')),
            None => PathBuf::from(path),
        };
        let listing = cx.background_spawn(async move {
            let mut entries = Vec::new();
            let mut children = fs.read_dir(&expanded).await?;
            while let Some(child) = children.next().await {
                let child = child?;
                if let Some(name) = child.file_name() {
                    entries.push((name.to_string_lossy().into_owned(), fs.is_dir(&child).await));
                }
            }
            anyhow::Ok((expanded.to_string_lossy().into_owned(), entries))
        });
        start_directory_load(&state, key, listing, cx);
        return success(&request.request_id, json!({ "state": "loading" }));
    };

    let project = browse_project(&state, host_id, &options, cx);
    let Some(project) = project else {
        return match state.workspaces.browse_projects.borrow().get(host_id) {
            Some(BrowseConnection::Failed) => {
                state
                    .workspaces
                    .browse_projects
                    .borrow_mut()
                    .remove(host_id);
                error(&request.request_id, "HOST_UNAVAILABLE")
            }
            _ => success(&request.request_id, json!({ "state": "connecting" })),
        };
    };
    let resolve = project.read(cx).resolve_abs_path(path, cx);
    let listing = cx.spawn(async move |cx| {
        let resolved = resolve
            .await
            .and_then(|resolved| resolved.into_abs_path())
            .ok_or_else(|| anyhow!("directory not found"))?;
        let items = project
            .update(cx, |project, cx| {
                project.list_directory(resolved.clone(), cx)
            })
            .await?;
        anyhow::Ok((
            resolved,
            items
                .into_iter()
                .filter_map(|item| {
                    let name = item.path.file_name()?.to_string_lossy().into_owned();
                    Some((name, item.is_dir))
                })
                .collect::<Vec<_>>(),
        ))
    });
    start_directory_load(&state, key, listing, cx);
    success(&request.request_id, json!({ "state": "loading" }))
}

fn start_directory_load(
    state: &Rc<ProbeState>,
    key: (String, String),
    listing: Task<Result<(String, Vec<(String, bool)>)>>,
    cx: &mut App,
) {
    state
        .workspaces
        .directories
        .borrow_mut()
        .insert(key.clone(), DirectoryRecord::Loading);
    let state = state.clone();
    cx.spawn(async move |_| {
        let record = match listing.await {
            Ok((path, mut entries)) => {
                entries.sort_by(|left, right| {
                    right
                        .1
                        .cmp(&left.1)
                        .then_with(|| left.0.to_lowercase().cmp(&right.0.to_lowercase()))
                });
                entries.truncate(MAX_DIRECTORY_ENTRIES);
                DirectoryRecord::Ready {
                    path,
                    entries: entries
                        .into_iter()
                        .map(|(name, is_dir)| json!({ "name": name, "is_dir": is_dir }))
                        .collect(),
                }
            }
            Err(listing_error) => {
                log::warn!("ZedLink directory listing failed: {listing_error:#}");
                DirectoryRecord::Failed
            }
        };
        state
            .workspaces
            .directories
            .borrow_mut()
            .insert(key, record);
    })
    .detach();
}

/// Mirrors Zed's remote project picker: browsing a host needs a live connection,
/// so reuse an open workspace on that host or connect with Zed's own modal.
fn browse_project(
    state: &Rc<ProbeState>,
    host_id: &str,
    options: &RemoteConnectionOptions,
    cx: &mut App,
) -> Option<Entity<project::Project>> {
    let open_project = open_workspaces(cx).into_iter().find_map(|workspace| {
        let project = workspace.read(cx).project().clone();
        let matches = project
            .read(cx)
            .remote_connection_options(cx)
            .is_some_and(|candidate| candidate.identity() == options.identity());
        (matches && !project.read(cx).is_disconnected(cx)).then_some(project)
    });
    if open_project.is_some() {
        return open_project;
    }
    match state.workspaces.browse_projects.borrow().get(host_id) {
        Some(BrowseConnection::Ready(project)) if !project.read(cx).is_disconnected(cx) => {
            return Some(project.clone());
        }
        Some(BrowseConnection::Connecting) | Some(BrowseConnection::Failed) => return None,
        _ => {}
    }
    let window = cx
        .active_window()
        .and_then(|window| window.downcast::<MultiWorkspace>())
        .or_else(|| multi_workspace_windows(cx).into_iter().next())?;
    state
        .workspaces
        .browse_projects
        .borrow_mut()
        .insert(host_id.to_string(), BrowseConnection::Connecting);
    let cleanup = (state.clone(), host_id.to_string());
    let host_id = host_id.to_string();
    let options = options.clone();
    let state = state.clone();
    let started = window.update(cx, |multi_workspace, window, cx| {
        let modal_workspace = multi_workspace.workspace().clone();
        let app_state = modal_workspace.read(cx).app_state().clone();
        let connect = remote_connection::connect_with_modal(&modal_workspace, options, window, cx);
        cx.spawn_in(window, async move |_, cx| {
            let client = connect.await;
            remote_connection::dismiss_connection_modal(&modal_workspace, cx);
            let record = match client {
                Ok(Some(client)) => cx.update(|_, cx| {
                    BrowseConnection::Ready(project::Project::remote(
                        client,
                        app_state.client.clone(),
                        app_state.node_runtime.clone(),
                        app_state.user_store.clone(),
                        app_state.languages.clone(),
                        app_state.fs.clone(),
                        true,
                        cx,
                    ))
                })?,
                Ok(None) => BrowseConnection::Failed,
                Err(connect_error) => {
                    log::warn!("ZedLink host connection failed: {connect_error:#}");
                    BrowseConnection::Failed
                }
            };
            state
                .workspaces
                .browse_projects
                .borrow_mut()
                .insert(host_id, record);
            anyhow::Ok(())
        })
        .detach_and_log_err(cx);
    });
    if started.is_err() {
        let (state, host_id) = cleanup;
        state
            .workspaces
            .browse_projects
            .borrow_mut()
            .remove(&host_id);
    }
    None
}
