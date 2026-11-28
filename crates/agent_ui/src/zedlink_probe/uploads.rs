use std::{sync::Arc, time::Instant};

use acp_thread::MentionUri;
use futures::{FutureExt as _, future::Shared};
use gpui::{AsyncApp, WeakEntity};
use project::{Project, ProjectPath, WorktreeId};
use util::ResultExt as _;

use super::*;

/// Raw bytes per chunk; base64 keeps a chunk request well below `MAX_REQUEST_BYTES`.
pub(super) const UPLOAD_CHUNK_BYTES: usize = 786_432;
const MAX_UPLOAD_FILE_BYTES: usize = 25 * 1024 * 1024;
const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const COMMITTED_UPLOAD_LIFETIME: Duration = Duration::from_secs(60 * 60);
const MAX_PENDING_UPLOADS: usize = 4;
const MAX_COMMITTED_UPLOADS: usize = 64;
const MAX_COMMITTED_IMAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_UPLOAD_REFS: usize = 10;
const MAX_FILE_NAME_BYTES: usize = 128;
const MAX_COLLISION_ATTEMPTS: usize = 1000;
const UPLOADS_DIRECTORY: &str = ".zlink/uploads";
const GIT_EXCLUDE_PATTERN: &str = ".zlink/";

#[derive(Default)]
pub(super) struct UploadState {
    pending: RefCell<HashMap<String, PendingUpload>>,
    committed: RefCell<VecDeque<CommittedUpload>>,
    reserved_paths: RefCell<HashSet<PathBuf>>,
    git_excluded_projects: RefCell<HashSet<String>>,
}

#[derive(Clone)]
struct UploadTarget {
    destination: UploadDestination,
    project_id: String,
    host_id: Value,
}

#[derive(Clone)]
enum UploadDestination {
    Worktree {
        project: WeakEntity<Project>,
        worktree_id: WorktreeId,
    },
    /// The canonical folder of a local project that is not open in Zed.
    Disk { root: PathBuf },
}

struct PendingUpload {
    target: UploadTarget,
    display_name: String,
    mime_type: String,
    last_activity: Instant,
    phase: UploadPhase,
}

enum UploadPhase {
    Receiving(ChunkBuffer),
    Committing(Shared<Task<std::result::Result<Value, &'static str>>>),
    Committed(Value),
}

struct CommittedUpload {
    project_id: String,
    relative_path: String,
    mime_type: String,
    image: Option<Arc<Vec<u8>>>,
    committed_at: Instant,
}

/// Accumulates an upload whose chunks must arrive strictly in order.
#[derive(Debug)]
struct ChunkBuffer {
    size: usize,
    data: Vec<u8>,
}

impl ChunkBuffer {
    fn new(size: usize) -> Self {
        Self {
            size,
            data: Vec::new(),
        }
    }

    fn is_complete(&self) -> bool {
        self.data.len() == self.size
    }

    fn append(&mut self, offset: u64, bytes: &[u8]) -> std::result::Result<usize, &'static str> {
        let offset = usize::try_from(offset).map_err(|_| "INVALID_REQUEST")?;
        if bytes.is_empty() || bytes.len() > UPLOAD_CHUNK_BYTES {
            return Err("INVALID_REQUEST");
        }
        let end = offset.checked_add(bytes.len()).ok_or("INVALID_REQUEST")?;
        // A client that lost the response to its last chunk resends it; accept that
        // exact repeat instead of failing an upload that is otherwise intact.
        if end == self.data.len() && self.data.get(offset..end) == Some(bytes) {
            return Ok(self.data.len());
        }
        if offset != self.data.len() || end > self.size {
            return Err("INVALID_REQUEST");
        }
        self.data.extend_from_slice(bytes);
        Ok(self.data.len())
    }
}

/// Keeps a phone-supplied name usable as a single path component on any host.
fn sanitize_file_name(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .chars()
        .map(|character| {
            if character.is_control()
                || character.is_whitespace()
                || matches!(character, ':' | '*' | '?' | '"' | '<' | '>' | '|' | '%')
            {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();
    let trimmed = base.trim_matches(|character| character == '.' || character == '_');
    let name = if trimmed.is_empty() {
        "upload"
    } else {
        trimmed
    };
    if name.len() <= MAX_FILE_NAME_BYTES {
        return name.to_string();
    }
    let (stem, extension) = split_extension(name);
    let extension = extension
        .filter(|extension| extension.len() <= 16)
        .map(|extension| format!(".{extension}"))
        .unwrap_or_default();
    let mut end = MAX_FILE_NAME_BYTES
        .saturating_sub(extension.len())
        .min(stem.len());
    while !stem.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{extension}", &stem[..end])
}

fn split_extension(name: &str) -> (&str, Option<&str>) {
    match name.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() && !extension.is_empty() => {
            (stem, Some(extension))
        }
        _ => (name, None),
    }
}

/// `attempt` 1 is the name itself, later attempts become `name-2.ext`, `name-3.ext`, ...
fn collision_candidate(name: &str, attempt: usize) -> String {
    if attempt <= 1 {
        return name.to_string();
    }
    match split_extension(name) {
        (stem, Some(extension)) => format!("{stem}-{attempt}.{extension}"),
        (stem, None) => format!("{stem}-{attempt}"),
    }
}

fn mime_type_for(name: &str, requested: Option<&str>) -> String {
    if let Some(requested) = requested
        .map(str::trim)
        .filter(|mime_type| !mime_type.is_empty() && mime_type.len() <= 128)
        .filter(|mime_type| {
            mime_type.split_once('/').is_some_and(|(kind, subtype)| {
                !kind.is_empty()
                    && !subtype.is_empty()
                    && mime_type
                        .chars()
                        .all(|character| character.is_ascii_graphic())
            })
        })
    {
        return requested.to_ascii_lowercase();
    }
    let extension = split_extension(name)
        .1
        .unwrap_or_default()
        .to_ascii_lowercase();
    match extension.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "heic" => "image/heic",
        "pdf" => "application/pdf",
        "json" => "application/json",
        "txt" | "log" => "text/plain",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Formats that agents accept as image content; anything else is only mentioned as a file.
fn is_attachable_image(mime_type: &str) -> bool {
    matches!(
        mime_type,
        "image/png" | "image/jpeg" | "image/webp" | "image/gif"
    )
}

fn upload_kind(mime_type: &str) -> &'static str {
    if is_attachable_image(mime_type) {
        "image"
    } else {
        "file"
    }
}

/// Accepts only `.zlink/uploads/YYYY-MM-DD/<name>` as produced by `project.upload.commit`.
fn parse_upload_ref(reference: &str) -> Option<&RelPath> {
    let rest = reference
        .strip_prefix(UPLOADS_DIRECTORY)?
        .strip_prefix('/')?;
    let (date, name) = rest.split_once('/')?;
    let date_is_valid = date.len() == 10
        && date.char_indices().all(|(index, character)| match index {
            4 | 7 => character == '-',
            _ => character.is_ascii_digit(),
        });
    if !date_is_valid
        || name.is_empty()
        || name.contains(['/', '\\'])
        || name.starts_with('.')
        || name.len() > MAX_FILE_NAME_BYTES * 2
        || sanitize_file_name(name) != name
    {
        return None;
    }
    RelPath::from_unix_str(reference).ok()
}

fn git_exclude_suffix(existing: &str) -> Option<&'static str> {
    let already_excluded = existing.lines().any(|line| {
        matches!(
            line.trim(),
            ".zlink" | ".zlink/" | "/.zlink" | "/.zlink/" | ".zlink/*" | "/.zlink/*"
        )
    });
    if already_excluded {
        None
    } else if existing.is_empty() || existing.ends_with('\n') {
        Some(".zlink/\n")
    } else {
        Some("\n.zlink/\n")
    }
}

/// The worktree uploads go to: the first folder of the workspace, as listed by `workspace.list`.
pub(super) fn upload_worktree(
    project: &Entity<Project>,
    cx: &App,
) -> Option<Entity<worktree::Worktree>> {
    let project = project.read(cx);
    let key = project.project_group_key(cx);
    let worktrees = project.visible_worktrees(cx).collect::<Vec<_>>();
    key.path_list()
        .paths()
        .first()
        .and_then(|first| {
            worktrees
                .iter()
                .find(|worktree| worktree.read(cx).abs_path().as_ref() == first.as_path())
                .cloned()
        })
        .or_else(|| worktrees.first().cloned())
}

fn upload_target(
    request: &ProbeRequest,
    state: &ProbeState,
    cx: &App,
) -> std::result::Result<UploadTarget, &'static str> {
    let thread_id = request.params.get("thread_id");
    let project_id = request.params.get("project_id");
    let project = match (thread_id, project_id) {
        (None, None) => return Err("INVALID_REQUEST"),
        (Some(thread_id), _) => {
            let thread_id = thread_id.as_str().ok_or("INVALID_REQUEST")?;
            let (thread, _) = exposed_thread_entry(thread_id, state, cx)?;
            thread.read(cx).project().clone()
        }
        (None, Some(project_id)) => {
            let project_id = project_id.as_str().ok_or("INVALID_REQUEST")?;
            match workspaces::resolve_project_id(project_id, state, cx)? {
                workspaces::ProjectLocation::Open(project) => project,
                workspaces::ProjectLocation::ClosedLocal(root) => {
                    return Ok(UploadTarget {
                        destination: UploadDestination::Disk { root },
                        project_id: project_id.to_string(),
                        host_id: json!(workspaces::host_id(None)),
                    });
                }
            }
        }
    };
    let workspace = workspaces::thread_workspace_value(&project, cx);
    let target_project_id = workspace["project_id"]
        .as_str()
        .ok_or("INVALID_REQUEST")?
        .to_string();
    if project_id.is_some_and(|project_id| project_id.as_str() != Some(&target_project_id)) {
        return Err("INVALID_REQUEST");
    }
    let worktree = upload_worktree(&project, cx).ok_or("UPLOAD_FAILED")?;
    Ok(UploadTarget {
        destination: UploadDestination::Worktree {
            project: project.downgrade(),
            worktree_id: worktree.read(cx).id(),
        },
        project_id: target_project_id,
        host_id: workspace["host_id"].clone(),
    })
}

pub(super) fn expire_uploads(state: &ProbeState) {
    let now = Instant::now();
    state.uploads.pending.borrow_mut().retain(|_, upload| {
        matches!(upload.phase, UploadPhase::Committing(_))
            || now.duration_since(upload.last_activity) < UPLOAD_IDLE_TIMEOUT
    });
    state
        .uploads
        .committed
        .borrow_mut()
        .retain(|upload| now.duration_since(upload.committed_at) < COMMITTED_UPLOAD_LIFETIME);
}

pub(super) fn upload_begin(request: &ProbeRequest, state: &ProbeState, cx: &mut App) -> Value {
    if !matches_instance(request, state) {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !params_contain_only(
        &request.params,
        &[
            "instance_id",
            "epoch",
            "thread_id",
            "project_id",
            "file_name",
            "mime_type",
            "size",
        ],
    ) {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let Some(file_name) = request
        .params
        .get("file_name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty() && name.len() <= 1024)
    else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let requested_mime_type = match request.params.get("mime_type") {
        None | Some(Value::Null) => None,
        Some(Value::String(mime_type)) => Some(mime_type.as_str()),
        Some(_) => return error(&request.request_id, "INVALID_REQUEST"),
    };
    let Some(size) = request.params.get("size").and_then(Value::as_u64) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    if size == 0 {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let size = match usize::try_from(size) {
        Ok(size) if size <= MAX_UPLOAD_FILE_BYTES => size,
        _ => return error(&request.request_id, "FILE_TOO_LARGE"),
    };
    let target = match upload_target(request, state, cx) {
        Ok(target) => target,
        Err(code) => return error(&request.request_id, code),
    };
    expire_uploads(state);
    let mut pending = state.uploads.pending.borrow_mut();
    if pending
        .values()
        .filter(|upload| !matches!(upload.phase, UploadPhase::Committed(_)))
        .count()
        >= MAX_PENDING_UPLOADS
    {
        return error(&request.request_id, "RATE_LIMITED");
    }
    let display_name = sanitize_file_name(file_name);
    let mime_type = mime_type_for(&display_name, requested_mime_type);
    let upload_id = uuid::Uuid::new_v4().to_string();
    pending.insert(
        upload_id.clone(),
        PendingUpload {
            target,
            display_name,
            mime_type,
            last_activity: Instant::now(),
            phase: UploadPhase::Receiving(ChunkBuffer::new(size)),
        },
    );
    success(
        &request.request_id,
        json!({ "upload_id": upload_id, "chunk_size": UPLOAD_CHUNK_BYTES }),
    )
}

fn requested_upload_id(request: &ProbeRequest) -> Option<&str> {
    request
        .params
        .get("upload_id")
        .and_then(Value::as_str)
        .filter(|upload_id| !upload_id.is_empty() && upload_id.len() <= 64)
}

pub(super) fn upload_chunk(request: &ProbeRequest, state: &ProbeState) -> Value {
    if !matches_instance(request, state) {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !params_contain_only(
        &request.params,
        &["instance_id", "epoch", "upload_id", "offset", "data"],
    ) {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let (Some(upload_id), Some(offset), Some(data)) = (
        requested_upload_id(request),
        request.params.get("offset").and_then(Value::as_u64),
        request.params.get("data").and_then(Value::as_str),
    ) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let Ok(bytes) = STANDARD.decode(data) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    expire_uploads(state);
    let mut pending = state.uploads.pending.borrow_mut();
    let Some(upload) = pending.get_mut(upload_id) else {
        return error(&request.request_id, "UNKNOWN_UPLOAD");
    };
    let UploadPhase::Receiving(buffer) = &mut upload.phase else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    match buffer.append(offset, &bytes) {
        Ok(received) => {
            upload.last_activity = Instant::now();
            success(&request.request_id, json!({ "received": received }))
        }
        Err(code) => error(&request.request_id, code),
    }
}

pub(super) fn upload_abort(request: &ProbeRequest, state: &ProbeState) -> Value {
    if !matches_instance(request, state) {
        return error(&request.request_id, "INSTANCE_UNAVAILABLE");
    }
    if !params_contain_only(&request.params, &["instance_id", "epoch", "upload_id"]) {
        return error(&request.request_id, "INVALID_REQUEST");
    }
    let Some(upload_id) = requested_upload_id(request) else {
        return error(&request.request_id, "INVALID_REQUEST");
    };
    let mut pending = state.uploads.pending.borrow_mut();
    match pending.get(upload_id).map(|upload| &upload.phase) {
        None => error(&request.request_id, "UNKNOWN_UPLOAD"),
        // The write is already running; the file stays and the commit result is kept.
        Some(UploadPhase::Committing(_)) | Some(UploadPhase::Committed(_)) => {
            success(&request.request_id, json!({}))
        }
        Some(UploadPhase::Receiving(_)) => {
            pending.remove(upload_id);
            success(&request.request_id, json!({}))
        }
    }
}

/// Resolves once the file is written. Repeating a commit for the same upload waits for the
/// same write, so a client that timed out can retry without creating a second file.
pub(super) fn upload_commit(
    request: &ProbeRequest,
    state: &Rc<ProbeState>,
    cx: &mut App,
) -> Task<Value> {
    let request_id = request.request_id.clone();
    if !matches_instance(request, state) {
        return Task::ready(error(&request_id, "INSTANCE_UNAVAILABLE"));
    }
    if !params_contain_only(&request.params, &["instance_id", "epoch", "upload_id"]) {
        return Task::ready(error(&request_id, "INVALID_REQUEST"));
    }
    let Some(upload_id) = requested_upload_id(request).map(str::to_string) else {
        return Task::ready(error(&request_id, "INVALID_REQUEST"));
    };
    expire_uploads(state);
    let mut pending = state.uploads.pending.borrow_mut();
    let Some(upload) = pending.get_mut(&upload_id) else {
        return Task::ready(error(&request_id, "UNKNOWN_UPLOAD"));
    };
    upload.last_activity = Instant::now();
    let write = match &mut upload.phase {
        UploadPhase::Committed(value) => return Task::ready(success(&request_id, value.clone())),
        UploadPhase::Committing(write) => write.clone(),
        UploadPhase::Receiving(buffer) => {
            if !buffer.is_complete() {
                return Task::ready(error(&request_id, "INVALID_REQUEST"));
            }
            let data = std::mem::take(&mut buffer.data);
            let write = cx
                .spawn({
                    let state = state.clone();
                    let target = upload.target.clone();
                    let display_name = upload.display_name.clone();
                    let mime_type = upload.mime_type.clone();
                    async move |cx| match &target.destination {
                        UploadDestination::Worktree {
                            project,
                            worktree_id,
                        } => {
                            write_upload(
                                &state,
                                &target,
                                project,
                                *worktree_id,
                                display_name,
                                mime_type,
                                data,
                                cx,
                            )
                            .await
                        }
                        UploadDestination::Disk { root } => {
                            write_disk_upload(
                                &state,
                                &target,
                                root,
                                display_name,
                                mime_type,
                                data,
                                cx,
                            )
                            .await
                        }
                    }
                })
                .shared();
            upload.phase = UploadPhase::Committing(write.clone());
            write
        }
    };
    drop(pending);
    let state = state.clone();
    cx.spawn(async move |_| {
        let result = write.await;
        let mut pending = state.uploads.pending.borrow_mut();
        match &result {
            Ok(value) => {
                if let Some(upload) = pending.get_mut(&upload_id) {
                    upload.phase = UploadPhase::Committed(value.clone());
                    upload.last_activity = Instant::now();
                }
            }
            Err(_) => {
                pending.remove(&upload_id);
            }
        }
        match result {
            Ok(value) => success(&request_id, value),
            Err(code) => error(&request_id, code),
        }
    })
}

fn uploads_directory() -> String {
    format!(
        "{UPLOADS_DIRECTORY}/{}",
        chrono::Local::now().format("%Y-%m-%d")
    )
}

fn committed_upload_value(
    target: &UploadTarget,
    relative_path: &str,
    abs_path: &Path,
    file_name: &str,
    mime_type: &str,
    size: usize,
) -> Value {
    json!({
        "upload_ref": relative_path,
        "abs_path": abs_path.to_string_lossy(),
        "relative_path": relative_path,
        "display_name": file_name,
        "mime_type": mime_type,
        "size": size,
        "kind": upload_kind(mime_type),
        "project_id": target.project_id,
        "host_id": target.host_id,
    })
}

async fn write_upload(
    state: &Rc<ProbeState>,
    target: &UploadTarget,
    project: &WeakEntity<Project>,
    worktree_id: WorktreeId,
    display_name: String,
    mime_type: String,
    data: Vec<u8>,
    cx: &mut AsyncApp,
) -> std::result::Result<Value, &'static str> {
    let project = project.upgrade().ok_or("UPLOAD_FAILED")?;
    let worktree = project
        .read_with(cx, |project, cx| project.worktree_for_id(worktree_id, cx))
        .ok_or("UPLOAD_FAILED")?;
    let directory = uploads_directory();

    let mut chosen = None;
    for attempt in 1..=MAX_COLLISION_ATTEMPTS {
        let file_name = collision_candidate(&display_name, attempt);
        let relative_path = format!("{directory}/{file_name}");
        let Ok(rel_path) = RelPath::from_unix_str(&relative_path) else {
            return Err("UPLOAD_FAILED");
        };
        let rel_path = rel_path.into_arc();
        let abs_path = worktree.read_with(cx, |worktree, _| worktree.absolutize(&rel_path));
        if state.uploads.reserved_paths.borrow().contains(&abs_path) {
            continue;
        }
        let exists = project
            .read_with(cx, |project, cx| project.host_path_is_dir(&abs_path, cx))
            .ok_or("UPLOAD_FAILED")?;
        match exists.await {
            Ok(None) => {
                chosen = Some((file_name, relative_path, rel_path, abs_path));
                break;
            }
            Ok(Some(_)) => {}
            Err(check_error) => {
                log::warn!("ZedLink upload target check failed: {check_error:#}");
                return Err("UPLOAD_FAILED");
            }
        }
    }
    let (file_name, relative_path, rel_path, abs_path) = chosen.ok_or("UPLOAD_FAILED")?;

    let size = data.len();
    let image = is_attachable_image(&mime_type).then(|| Arc::new(data.clone()));
    state
        .uploads
        .reserved_paths
        .borrow_mut()
        .insert(abs_path.clone());
    // `Worktree::create_entry` writes through the remote server for SSH workspaces.
    let created = worktree
        .update(cx, |worktree, cx| {
            worktree.create_entry(rel_path, false, Some(data), cx)
        })
        .await;
    state.uploads.reserved_paths.borrow_mut().remove(&abs_path);
    if let Err(write_error) = created {
        log::warn!("ZedLink upload could not be written: {write_error:#}");
        return Err("UPLOAD_FAILED");
    }

    if !state
        .uploads
        .git_excluded_projects
        .borrow()
        .contains(&target.project_id)
    {
        match exclude_uploads_from_git(&project, &worktree, cx).await {
            Ok(()) => {
                state
                    .uploads
                    .git_excluded_projects
                    .borrow_mut()
                    .insert(target.project_id.clone());
            }
            Err(exclude_error) => {
                log::warn!("ZedLink could not add .zlink/ to .git/info/exclude: {exclude_error:#}")
            }
        }
    }

    remember_committed_upload(
        state,
        CommittedUpload {
            project_id: target.project_id.clone(),
            relative_path: relative_path.clone(),
            mime_type: mime_type.clone(),
            image,
            committed_at: Instant::now(),
        },
    );
    Ok(committed_upload_value(
        target,
        &relative_path,
        &abs_path,
        &file_name,
        &mime_type,
        size,
    ))
}

async fn write_disk_upload(
    state: &Rc<ProbeState>,
    target: &UploadTarget,
    root: &Path,
    display_name: String,
    mime_type: String,
    data: Vec<u8>,
    cx: &mut AsyncApp,
) -> std::result::Result<Value, &'static str> {
    let size = data.len();
    let image = is_attachable_image(&mime_type).then(|| Arc::new(data.clone()));
    let directory = uploads_directory();
    let (file_name, relative_path, abs_path) = cx
        .background_spawn({
            let root = root.to_path_buf();
            let display_name = display_name.clone();
            async move { write_disk_upload_file(&root, &directory, &display_name, &data) }
        })
        .await?;

    if !state
        .uploads
        .git_excluded_projects
        .borrow()
        .contains(&target.project_id)
    {
        let root = root.to_path_buf();
        match cx
            .background_spawn(async move { exclude_disk_uploads_from_git(&root) })
            .await
        {
            Ok(()) => {
                state
                    .uploads
                    .git_excluded_projects
                    .borrow_mut()
                    .insert(target.project_id.clone());
            }
            Err(exclude_error) => {
                log::warn!("ZedLink could not add .zlink/ to .git/info/exclude: {exclude_error:#}")
            }
        }
    }

    remember_committed_upload(
        state,
        CommittedUpload {
            project_id: target.project_id.clone(),
            relative_path: relative_path.clone(),
            mime_type: mime_type.clone(),
            image,
            committed_at: Instant::now(),
        },
    );
    Ok(committed_upload_value(
        target,
        &relative_path,
        &abs_path,
        &file_name,
        &mime_type,
        size,
    ))
}

/// Creates the file with `create_new`, so a concurrent upload or an existing file is never
/// overwritten, and refuses an uploads directory that resolves outside the project.
fn write_disk_upload_file(
    root: &Path,
    directory: &str,
    display_name: &str,
    data: &[u8],
) -> std::result::Result<(String, String, PathBuf), &'static str> {
    let target_directory = root.join(directory);
    fs::create_dir_all(&target_directory).map_err(|create_error| {
        log::warn!("ZedLink upload directory could not be created: {create_error:#}");
        "UPLOAD_FAILED"
    })?;
    let target_directory = fs::canonicalize(&target_directory).map_err(|_| "UPLOAD_FAILED")?;
    if !target_directory.starts_with(root) {
        return Err("UPLOAD_FAILED");
    }
    for attempt in 1..=MAX_COLLISION_ATTEMPTS {
        let file_name = collision_candidate(display_name, attempt);
        let abs_path = target_directory.join(&file_name);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&abs_path);
        let mut file = match file {
            Ok(file) => file,
            Err(open_error) if open_error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(open_error) => {
                log::warn!("ZedLink upload could not be created: {open_error:#}");
                return Err("UPLOAD_FAILED");
            }
        };
        if let Err(write_error) = file.write_all(data).and_then(|()| file.sync_all()) {
            log::warn!("ZedLink upload could not be written: {write_error:#}");
            fs::remove_file(&abs_path).log_err();
            return Err("UPLOAD_FAILED");
        }
        return Ok((
            file_name.clone(),
            format!("{directory}/{file_name}"),
            abs_path,
        ));
    }
    Err("UPLOAD_FAILED")
}

/// Only a plain `.git` directory in the project folder or above is handled; linked worktrees
/// (a `.git` file) are left alone, as for remote workspaces.
fn exclude_disk_uploads_from_git(root: &Path) -> Result<()> {
    let Some(git_directory) = root
        .ancestors()
        .map(|ancestor| ancestor.join(".git"))
        .find(|git| git.exists())
        .filter(|git| git.is_dir())
    else {
        return Ok(());
    };
    let exclude_path = git_directory.join("info").join("exclude");
    let existing = match fs::read_to_string(&exclude_path) {
        Ok(existing) => existing,
        Err(read_error) if read_error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(read_error) => return Err(read_error.into()),
    };
    if let Some(suffix) = git_exclude_suffix(&existing) {
        fs::create_dir_all(git_directory.join("info"))?;
        fs::write(&exclude_path, format!("{existing}{suffix}"))?;
    }
    Ok(())
}

fn remember_committed_upload(state: &ProbeState, upload: CommittedUpload) {
    let mut committed = state.uploads.committed.borrow_mut();
    committed.retain(|existing| {
        existing.project_id != upload.project_id || existing.relative_path != upload.relative_path
    });
    committed.push_back(upload);
    while committed.len() > MAX_COMMITTED_UPLOADS
        || committed
            .iter()
            .filter_map(|upload| upload.image.as_ref())
            .map(|image| image.len())
            .sum::<usize>()
            > MAX_COMMITTED_IMAGE_BYTES
    {
        if committed.pop_front().is_none() {
            break;
        }
    }
}

async fn exclude_uploads_from_git(
    project: &Entity<Project>,
    worktree: &Entity<worktree::Worktree>,
    cx: &mut AsyncApp,
) -> Result<()> {
    let (root, worktree_id, exclude_path, is_local, path_style, fs) =
        project.read_with(cx, |project, cx| {
            let root = worktree.read(cx).abs_path();
            let exclude_path = project
                .git_store()
                .read(cx)
                .repositories()
                .values()
                .map(|repository| repository.read(cx))
                .filter(|repository| root.starts_with(&repository.work_directory_abs_path))
                .max_by_key(|repository| repository.work_directory_abs_path.as_os_str().len())
                .map(|repository| repository.common_dir_abs_path.join("info").join("exclude"));
            (
                root,
                worktree.read(cx).id(),
                exclude_path,
                project.is_local(),
                project.path_style(cx),
                project.fs().clone(),
            )
        });
    let Some(exclude_path) = exclude_path else {
        return Ok(());
    };
    let exists = project
        .read_with(cx, |project, cx| {
            project.host_path_is_dir(&exclude_path, cx)
        })
        .context("workspace host unavailable")?
        .await?
        .is_some();

    if is_local {
        let existing = if exists {
            fs.load(&exclude_path).await?
        } else {
            String::new()
        };
        if let Some(suffix) = git_exclude_suffix(&existing) {
            fs.write(&exclude_path, format!("{existing}{suffix}").as_bytes())
                .await?;
        }
        return Ok(());
    }

    // Remote workspaces can only be written inside a worktree, so a Git directory
    // outside the opened folder (linked worktrees, nested folders) is left alone.
    let relative = exclude_path
        .strip_prefix(&root)
        .context("Git directory is outside the remote workspace")?;
    let relative = RelPath::new(relative, path_style)?.as_ref().into_arc();
    if !exists {
        worktree
            .update(cx, |worktree, cx| {
                worktree.create_entry(
                    relative,
                    false,
                    Some(format!("{GIT_EXCLUDE_PATTERN}\n").into_bytes()),
                    cx,
                )
            })
            .await?;
        return Ok(());
    }
    let buffer = project
        .update(cx, |project, cx| {
            project.open_buffer(
                ProjectPath {
                    worktree_id,
                    path: relative,
                },
                cx,
            )
        })
        .await?;
    let existing = buffer.read_with(cx, |buffer, _| buffer.text());
    let Some(suffix) = git_exclude_suffix(&existing) else {
        return Ok(());
    };
    buffer.update(cx, |buffer, cx| {
        let end = buffer.len();
        buffer.edit([(end..end, suffix)], None, cx);
    });
    project
        .update(cx, |project, cx| project.save_buffer(buffer, cx))
        .await
}

/// Content blocks for `thread.send`'s `upload_refs`: a file mention for every upload, plus the
/// image itself for images, so the agent both sees the path and can look at the picture.
pub(super) fn upload_ref_content(
    request: &ProbeRequest,
    thread: &Entity<AcpThread>,
    state: &ProbeState,
    cx: &App,
) -> std::result::Result<Vec<acp::ContentBlock>, &'static str> {
    let references = match request.params.get("upload_refs") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(references)) if references.len() <= MAX_UPLOAD_REFS => references,
        Some(_) => return Err("INVALID_REQUEST"),
    };
    if references.is_empty() {
        return Ok(Vec::new());
    }
    let project = thread.read(cx).project().clone();
    let project_id = workspaces::thread_workspace_value(&project, cx)["project_id"]
        .as_str()
        .map(str::to_string)
        .ok_or("INVALID_REQUEST")?;
    let worktree = upload_worktree(&project, cx).ok_or("INVALID_REQUEST")?;
    let is_local = project.read(cx).is_local();
    let uploads_root = worktree
        .read(cx)
        .absolutize(RelPath::from_unix_str(UPLOADS_DIRECTORY).map_err(|_| "INVALID_REQUEST")?);
    expire_uploads(state);

    let mut content = Vec::new();
    for reference in references {
        let reference = reference.as_str().ok_or("INVALID_REQUEST")?;
        let rel_path = parse_upload_ref(reference).ok_or("INVALID_REQUEST")?;
        let abs_path = worktree.read(cx).absolutize(rel_path);
        let committed = state
            .uploads
            .committed
            .borrow()
            .iter()
            .find(|upload| upload.project_id == project_id && upload.relative_path == reference)
            .map(|upload| (upload.mime_type.clone(), upload.image.clone()));
        let (mime_type, image) = match committed {
            Some((mime_type, image)) => (mime_type, image),
            None if is_local => {
                let canonical_root =
                    fs::canonicalize(&uploads_root).map_err(|_| "INVALID_REQUEST")?;
                let canonical = fs::canonicalize(&abs_path).map_err(|_| "INVALID_REQUEST")?;
                if !canonical.starts_with(&canonical_root) || !canonical.is_file() {
                    return Err("INVALID_REQUEST");
                }
                let mime_type = mime_type_for(reference, None);
                let image = if is_attachable_image(&mime_type) {
                    match fs::metadata(&canonical) {
                        Ok(metadata) if metadata.len() <= MAX_UPLOAD_FILE_BYTES as u64 => Some(
                            Arc::new(fs::read(&canonical).map_err(|_| "INVALID_REQUEST")?),
                        ),
                        _ => None,
                    }
                } else {
                    None
                };
                (mime_type, image)
            }
            // A remote upload from an earlier session can't be checked synchronously; the
            // agent still gets the path, which the remote tools resolve themselves.
            None => (mime_type_for(reference, None), None),
        };
        let mention = MentionUri::File {
            abs_path: abs_path.clone(),
        };
        content.push(acp::ContentBlock::ResourceLink(acp::ResourceLink::new(
            mention.name(),
            mention.to_uri().to_string(),
        )));
        if let Some(image) = image.filter(|_| is_attachable_image(&mime_type)) {
            content.push(acp::ContentBlock::Image(acp::ImageContent::new(
                STANDARD.encode(image.as_slice()),
                mime_type,
            )));
        }
    }
    Ok(content)
}

pub(super) fn has_upload_refs(params: &Value) -> bool {
    params
        .get("upload_refs")
        .and_then(Value::as_array)
        .is_some_and(|references| !references.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_file_names() {
        assert_eq!(sanitize_file_name("photo.jpg"), "photo.jpg");
        assert_eq!(sanitize_file_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name("C:\\Users\\me\\shot.png"), "shot.png");
        assert_eq!(sanitize_file_name("my photo (1).HEIC"), "my_photo_(1).HEIC");
        assert_eq!(sanitize_file_name(".hidden"), "hidden");
        assert_eq!(sanitize_file_name("..."), "upload");
        assert_eq!(sanitize_file_name("a\u{0}b?c|d.txt"), "a_b_c_d.txt");
        assert_eq!(sanitize_file_name("Снимок экрана.png"), "Снимок_экрана.png");
        assert_eq!(sanitize_file_name("dir/"), "upload");

        let long = format!("{}.jpeg", "я".repeat(200));
        let sanitized = sanitize_file_name(&long);
        assert!(sanitized.len() <= MAX_FILE_NAME_BYTES);
        assert!(sanitized.ends_with(".jpeg"));
    }

    #[test]
    fn collision_candidates_add_numeric_suffixes() {
        assert_eq!(collision_candidate("photo.jpg", 1), "photo.jpg");
        assert_eq!(collision_candidate("photo.jpg", 2), "photo-2.jpg");
        assert_eq!(collision_candidate("photo.jpg", 3), "photo-3.jpg");
        assert_eq!(collision_candidate("archive.tar.gz", 2), "archive.tar-2.gz");
        assert_eq!(collision_candidate("README", 2), "README-2");
        for attempt in 1..5 {
            let candidate = collision_candidate("photo.jpg", attempt);
            assert_eq!(sanitize_file_name(&candidate), candidate);
        }
    }

    #[test]
    fn chunks_must_arrive_in_order() {
        let mut buffer = ChunkBuffer::new(6);
        assert_eq!(buffer.append(0, b"abc"), Ok(3));
        assert_eq!(
            buffer.append(0, b"abc"),
            Ok(3),
            "a resent last chunk is accepted"
        );
        assert_eq!(
            buffer.append(1, b"bc"),
            Ok(3),
            "the same tail is accepted too"
        );
        assert_eq!(buffer.append(4, b"ef"), Err("INVALID_REQUEST"), "gap");
        assert_eq!(buffer.append(0, b"xyz"), Err("INVALID_REQUEST"), "rewrite");
        assert_eq!(
            buffer.append(3, b"defg"),
            Err("INVALID_REQUEST"),
            "too long"
        );
        assert_eq!(buffer.append(3, b""), Err("INVALID_REQUEST"), "empty");
        assert!(!buffer.is_complete());
        assert_eq!(buffer.append(3, b"def"), Ok(6));
        assert!(buffer.is_complete());
        assert_eq!(buffer.data, b"abcdef");
        assert_eq!(buffer.append(6, b"g"), Err("INVALID_REQUEST"));
        assert_eq!(buffer.append(u64::MAX, b"g"), Err("INVALID_REQUEST"));
    }

    #[test]
    fn validates_upload_refs() {
        assert!(parse_upload_ref(".zlink/uploads/2026-11-27/photo.jpg").is_some());
        assert!(parse_upload_ref(".zlink/uploads/2026-11-27/photo-2.jpg").is_some());
        assert!(parse_upload_ref(".zlink/uploads/2026-11-27/Снимок.png").is_some());
        for invalid in [
            "",
            "photo.jpg",
            "/abs/.zlink/uploads/2026-11-27/photo.jpg",
            ".zlink/uploads/photo.jpg",
            ".zlink/uploads/2026-11-27/",
            ".zlink/uploads/2026-11-27/../secret",
            ".zlink/uploads/2026-11-27/a/b.jpg",
            ".zlink/uploads/2026-11-27/.env",
            ".zlink/uploads/2026-1-27/photo.jpg",
            ".zlink/uploads/../uploads/2026-11-27/photo.jpg",
            ".zlink/uploads/2026-11-27/a b.jpg",
            ".zlink/other/2026-11-27/photo.jpg",
            "src/main.rs",
        ] {
            assert!(parse_upload_ref(invalid).is_none(), "{invalid:?}");
        }
    }

    #[test]
    fn detects_mime_types_and_kinds() {
        assert_eq!(mime_type_for("a.JPG", None), "image/jpeg");
        assert_eq!(mime_type_for("a.bin", Some("Image/PNG")), "image/png");
        assert_eq!(mime_type_for("a.png", Some("not a mime")), "image/png");
        assert_eq!(mime_type_for("a", None), "application/octet-stream");
        assert_eq!(upload_kind("image/png"), "image");
        assert_eq!(upload_kind("image/heic"), "file");
        assert_eq!(upload_kind("application/pdf"), "file");
    }

    #[test]
    fn appends_git_exclude_once() {
        assert_eq!(git_exclude_suffix(""), Some(".zlink/\n"));
        assert_eq!(git_exclude_suffix("# comment\n"), Some(".zlink/\n"));
        assert_eq!(git_exclude_suffix("target"), Some("\n.zlink/\n"));
        assert_eq!(git_exclude_suffix("a\n.zlink/\n"), None);
        assert_eq!(git_exclude_suffix("/.zlink\n"), None);
    }
}
