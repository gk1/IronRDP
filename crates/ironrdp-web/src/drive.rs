//! Browser-memory filesystem used by the StoneVeyl RDPDR redirector.
//!
//! The browser never exposes an arbitrary local path.  The embedding page
//! explicitly seeds this store from files chosen by the user and may later
//! offer files created by Windows as browser downloads.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use futures_channel::mpsc;

use ironrdp::rdpdr::backend::RdpdrBackend;
use ironrdp::rdpdr::pdu::RdpdrPdu;
use ironrdp::rdpdr::pdu::efs::{
    Boolean, ClientDriveLockControlResponse, ClientDriveNotifyChangeDirectoryResponse,
    ClientDriveQueryDirectoryResponse, ClientDriveQueryInformationResponse,
    ClientDriveQuerySecurityResponse, ClientDriveQueryVolumeInformationResponse,
    ClientDriveSetInformationResponse, ClientDriveSetSecurityResponse, CreateDisposition,
    CreateOptions, DeviceCloseResponse, DeviceControlRequest, DeviceControlResponse,
    DeviceCreateRequest, DeviceCreateResponse, DeviceFlushBuffersResponse, DeviceIoResponse,
    DeviceReadRequest, DeviceReadResponse, DeviceWriteRequest, DeviceWriteResponse,
    FileAttributeTagInformation, FileAttributes, FileBasicInformation, FileBothDirectoryInformation,
    FileDirectoryInformation, FileFullDirectoryInformation, FileInformationClass,
    FileInformationClassLevel, FileNamesInformation, FileStandardInformation,
    FileSystemAttributes, FileSystemInformationClass, FileSystemInformationClassLevel,
    FileFsAttributeInformation, FileFsFullSizeInformation, FileFsSizeInformation,
    FileFsVolumeInformation, Information, NtStatus, PrinterIoRequest, ServerDeviceAnnounceResponse,
    ServerDriveIoRequest, ServerDriveQueryDirectoryRequest,
};
use ironrdp::rdpdr::pdu::esc::{ScardCall, ScardIoCtlCode};
use ironrdp_core::impl_as_any;
use ironrdp_pdu::{PduResult, encode_err};
use ironrdp_svc::SvcMessage;
use tracing::{debug, error, warn};
use wasm_bindgen::prelude::*;

use crate::session::RdpInputEvent;

/// One file copied from the browser into a virtual redirected drive.
#[derive(Clone, Debug)]
pub(crate) struct DriveSeedFile {
    pub(crate) name: String,
    pub(crate) size: u64,
    /// Unix milliseconds from the browser's native `File.lastModified`.
    pub(crate) last_modified: i64,
}

// A valid, fixed FILETIME for the browser-backed virtual filesystem. The
// browser selection API exposes names and sizes without portable directory
// timestamps, but Windows Explorer expects a valid FILETIME in directory and
// basic-information replies rather than the all-zero sentinel used by the
// initial prototype. 2024-01-01T00:00:00Z is deliberately stable for the
// lifetime of a mounted virtual drive.
const VIRTUAL_DRIVE_FILETIME: i64 = 133_485_408_000_000_000;

const WINDOWS_EPOCH_OFFSET_100NS: i64 = 116_444_736_000_000_000;

fn filetime_from_unix_millis(millis: i64) -> i64 {
    millis
        .saturating_mul(10_000)
        .saturating_add(WINDOWS_EPOCH_OFFSET_100NS)
}

/// A deliberately small, path-confined filesystem model.  RDPDR paths are
/// Windows paths; internally they are normalized to slash-delimited relative
/// paths.  A path containing `..` is rejected before it can touch the store.
#[derive(Debug, Default)]
pub(crate) struct VirtualDrive {
    files: HashMap<String, VirtualFile>,
    directories: BTreeMap<String, i64>,
}

/// A selected browser file starts metadata-only. Files created by Windows are
/// held temporarily until the browser persists or downloads them on close.
#[derive(Clone, Debug, Default)]
struct VirtualFile {
    size: u64,
    data: Option<Vec<u8>>,
    last_modified: i64,
}

impl VirtualDrive {
    pub(crate) fn from_seed_files(files: Vec<DriveSeedFile>) -> Self {
        let mut drive = Self::default();
        drive.directories.insert(String::new(), VIRTUAL_DRIVE_FILETIME);
        for file in files {
            let Ok(path) = Self::normalize(&file.name) else { continue };
            if path.is_empty() { continue }
            drive.ensure_parents(&path);
            drive.files.insert(path, VirtualFile { size: file.size, data: None, last_modified: filetime_from_unix_millis(file.last_modified) });
        }
        drive
    }

    pub(crate) fn normalize(path: &str) -> Result<String, ()> {
        let mut out = Vec::new();
        let normalized = path.replace('\\', "/");
        for part in normalized.split('/') {
            if part.is_empty() || part == "." { continue }
            if part == ".." || part.contains('\0') { return Err(()) }
            out.push(part);
        }
        Ok(out.join("/"))
    }

    fn directory_query_path(&self, open_handle_path: &str, requested_path: &str) -> Result<String, ()> {
        let requested_path = requested_path.trim_end_matches('*').trim_end_matches(['\\', '/']);
        let requested_path = Self::normalize(requested_path)?;
        if requested_path.is_empty() {
            return Ok(open_handle_path.to_owned());
        }
        if self.is_dir(&requested_path) || self.file_size(&requested_path).is_some() {
            return Ok(requested_path);
        }
        if !open_handle_path.is_empty() {
            let relative_path = format!("{open_handle_path}/{requested_path}");
            if self.is_dir(&relative_path) || self.file_size(&relative_path).is_some() {
                return Ok(relative_path);
            }
        }
        Ok(requested_path)
    }

    pub(crate) fn is_dir(&self, path: &str) -> bool { self.directories.contains_key(path) }
    pub(crate) fn file_size(&self, path: &str) -> Option<u64> { self.files.get(path).map(|file| file.size) }
    pub(crate) fn file_data(&self, path: &str) -> Option<&[u8]> { self.files.get(path).and_then(|file| file.data.as_deref()) }

    fn metadata(&self, path: &str) -> Option<(bool, u64, i64)> {
        self.files.get(path)
            .map(|file| (false, file.size, file.last_modified))
            .or_else(|| self.directories.get(path).map(|time| (true, 0, *time)))
    }

    fn create_file(&mut self, path: String) -> &mut VirtualFile {
        self.ensure_parents(&path);
        self.files.entry(path).or_insert_with(|| VirtualFile { size: 0, data: None, last_modified: VIRTUAL_DRIVE_FILETIME })
    }

    pub(crate) fn create_dir(&mut self, path: String) {
        self.ensure_parents(&path);
        self.directories.insert(path, VIRTUAL_DRIVE_FILETIME);
    }

    fn remove(&mut self, path: &str) {
        self.files.remove(path);
        self.directories.remove(path);
    }

    fn rename(&mut self, from: &str, to: String) -> bool {
        if let Some(data) = self.files.remove(from) {
            self.ensure_parents(&to);
            self.files.insert(to, data);
            return true;
        }
        if !self.directories.contains_key(from) || from.is_empty() { return false; }
        let prefix = format!("{from}/");
        let directories = self.directories.iter().filter(|(path, _)| *path == from || path.starts_with(&prefix)).map(|(path, time)| (path.clone(), *time)).collect::<Vec<_>>();
        let files = self.files.iter().filter(|(path, _)| *path == from || path.starts_with(&prefix)).map(|(path, data)| (path.clone(), data.clone())).collect::<Vec<_>>();
        self.ensure_parents(&to);
        for (path, _) in &directories { self.directories.remove(path); }
        for (path, _) in &files { self.files.remove(path); }
        for (path, time) in directories {
            let suffix = path.strip_prefix(from).expect("selected rename directory path");
            self.directories.insert(format!("{to}{suffix}"), time);
        }
        for (path, data) in files {
            let suffix = path.strip_prefix(from).expect("selected rename file path");
            self.files.insert(format!("{to}{suffix}"), data);
        }
        true
    }

    pub(crate) fn children(&self, dir: &str) -> Vec<(String, bool, usize, i64)> {
        let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
        let mut children = BTreeSet::new();
        for path in self.directories.keys().chain(self.files.keys()) {
            let Some(rest) = path.strip_prefix(&prefix) else { continue };
            let Some(name) = rest.split('/').next() else { continue };
            if !name.is_empty() { children.insert(name.to_owned()); }
        }
        children.into_iter().map(|name| {
            let path = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
            let (directory, size, last_modified) = self.metadata(&path).expect("child has metadata");
            (name, directory, size.try_into().unwrap_or(usize::MAX), last_modified)
        }).collect()
    }

    fn ensure_parents(&mut self, path: &str) {
        self.directories.entry(String::new()).or_insert(VIRTUAL_DRIVE_FILETIME);
        let mut current = String::new();
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_none() { break }
            if !current.is_empty() { current.push('/'); }
            current.push_str(part);
            self.directories.entry(current.clone()).or_insert(VIRTUAL_DRIVE_FILETIME);
        }
    }
}

#[derive(Debug)]
struct OpenHandle {
    path: String,
    directory: bool,
    children: Option<Vec<(String, bool, usize, i64)>>,
    written: bool,
}

/// Server-created file which the browser should offer to the user after the
/// RDP application closes its handle. This is the reverse side of drive
/// redirection: a Save As operation in Windows becomes an explicit browser
/// download, never a silent write to the local filesystem.
#[derive(Debug)]
pub(crate) enum DriveBackendMessage {
    ReadRequested { request_id: u32, name: String, offset: u64, length: u32 },
    Completed { name: String, data: Vec<u8> },
    Diagnostic(String),
}

#[derive(Debug, Clone)]
pub(crate) struct WasmDriveMessageProxy {
    tx: mpsc::UnboundedSender<RdpInputEvent>,
}

impl WasmDriveMessageProxy {
    fn new(tx: mpsc::UnboundedSender<RdpInputEvent>) -> Self { Self { tx } }

    fn send_completed(&self, name: String, data: Vec<u8>) {
        if self.tx.unbounded_send(RdpInputEvent::Drive(DriveBackendMessage::Completed { name, data })).is_err() {
            error!("Failed to queue redirected-drive download; session event loop is closed");
        }
    }

    fn send_read_requested(&self, request_id: u32, name: String, offset: u64, length: u32) {
        if self.tx.unbounded_send(RdpInputEvent::Drive(DriveBackendMessage::ReadRequested { request_id, name, offset, length })).is_err() {
            error!("Failed to queue redirected-drive read; session event loop is closed");
        }
    }

    fn send_diagnostic(&self, message: String) {
        if self.tx.unbounded_send(RdpInputEvent::Drive(DriveBackendMessage::Diagnostic(message))).is_err() {
            error!("Failed to queue redirected-drive diagnostic; session event loop is closed");
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct JsDriveCallbacks {
    /// `function(requestID: number, name: string, offset: number, length: number): void`
    /// invoked when Windows reads a range from a browser-selected file.
    pub(crate) on_file_read: js_sys::Function,
    /// `function(name: string, data: Uint8Array): void` invoked after a
    /// Windows-created file is closed by the remote application.
    pub(crate) on_file_written: js_sys::Function,
    /// Optional local-only protocol trace used to troubleshoot browser drive
    /// compatibility. It is never sent to the gateway or control plane.
    pub(crate) on_diagnostic: Option<js_sys::Function>,
}

#[derive(Debug)]
pub(crate) struct WasmDrive {
    callbacks: JsDriveCallbacks,
}

impl WasmDrive {
    fn new(callbacks: JsDriveCallbacks) -> Self { Self { callbacks } }

    /// Reports a local diagnostic directly to the embedding page. This path is
    /// intentionally synchronous so a protocol error can be displayed even
    /// when the RDP session event loop is about to terminate.
    pub(crate) fn report_diagnostic(&self, message: String) {
        if let Some(callback) = &self.callbacks.on_diagnostic {
            if let Err(err) = callback.call1(&JsValue::NULL, &JsValue::from(message)) {
                error!(?err, "on_diagnostic JS callback threw");
            }
        }
    }

    pub(crate) fn process_message(&self, message: DriveBackendMessage) {
        match message {
            DriveBackendMessage::Completed { name, data } => {
                let bytes = js_sys::Uint8Array::from(data.as_slice());
                if let Err(err) = self.callbacks.on_file_written.call2(&JsValue::NULL, &JsValue::from(name), &bytes) {
                    error!(?err, "on_file_written JS callback threw");
                }
            }
            DriveBackendMessage::ReadRequested { request_id, name, offset, length } => {
                if let Err(err) = self.callbacks.on_file_read.call4(
                    &JsValue::NULL,
                    &JsValue::from_f64(f64::from(request_id)),
                    &JsValue::from(name),
                    &JsValue::from_f64(offset as f64),
                    &JsValue::from_f64(f64::from(length)),
                ) {
                    error!(?err, "on_file_read JS callback threw");
                }
            }
            DriveBackendMessage::Diagnostic(message) => {
                self.report_diagnostic(message);
            }
        }
    }
}

pub(crate) fn wasm_drive_pair(
    input_events_tx: mpsc::UnboundedSender<RdpInputEvent>,
    files: Vec<DriveSeedFile>,
    callbacks: JsDriveCallbacks,
) -> (WasmDriveBackend, WasmDrive) {
    let backend = WasmDriveBackend::new(files, WasmDriveMessageProxy::new(input_events_tx));
    (backend, WasmDrive::new(callbacks))
}

/// RDPDR backend for the browser's explicitly-selected virtual drive.
///
/// It intentionally operates only on the in-memory `VirtualDrive`; no server
/// request can escape that selected tree to access the user's device.
#[derive(Debug)]
pub(crate) struct WasmDriveBackend {
    drive: VirtualDrive,
    next_file_id: u32,
    handles: HashMap<u32, OpenHandle>,
    proxy: WasmDriveMessageProxy,
    next_read_request_id: u32,
    pending_reads: HashMap<u32, DeviceReadRequest>,
}

impl_as_any!(WasmDriveBackend);

impl WasmDriveBackend {
    pub(crate) fn new(files: Vec<DriveSeedFile>, proxy: WasmDriveMessageProxy) -> Self {
        Self { drive: VirtualDrive::from_seed_files(files), next_file_id: 1, handles: HashMap::new(), proxy, next_read_request_id: 1, pending_reads: HashMap::new() }
    }

    fn allocate_file_id(&mut self) -> u32 {
        let id = self.next_file_id;
        self.next_file_id = self.next_file_id.wrapping_add(1).max(1);
        id
    }

    fn response(request: ironrdp::rdpdr::pdu::efs::DeviceIoRequest, status: NtStatus) -> DeviceIoResponse {
        DeviceIoResponse::new(request, status)
    }

    fn create(&mut self, req: DeviceCreateRequest) -> PduResult<Vec<SvcMessage>> {
        let request = req.device_io_request;
        let Ok(path) = VirtualDrive::normalize(&req.path) else {
            self.proxy.send_diagnostic(format!("create rejected path={}", req.path));
            return Ok(vec![SvcMessage::from(RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
                device_io_reply: Self::response(request, NtStatus::ACCESS_DENIED), file_id: 0, information: Information::empty(),
            }))]);
        };
        let wants_directory = req.create_options.contains(CreateOptions::FILE_DIRECTORY_FILE);
        let must_be_file = req.create_options.contains(CreateOptions::FILE_NON_DIRECTORY_FILE);
        let exists_dir = self.drive.is_dir(&path);
        let exists_file = self.drive.file_size(&path).is_some();
        let exists = exists_dir || exists_file;
        let may_create = matches!(req.create_disposition, CreateDisposition::FILE_CREATE | CreateDisposition::FILE_OPEN_IF | CreateDisposition::FILE_OVERWRITE_IF | CreateDisposition::FILE_SUPERSEDE);
        if (exists && req.create_disposition == CreateDisposition::FILE_CREATE) || (!exists && !may_create) || (exists_dir && must_be_file) || (exists_file && wants_directory) {
            self.proxy.send_diagnostic(format!("create path={path} status=NO_SUCH_FILE exists={exists} directory={exists_dir}"));
            return Ok(vec![SvcMessage::from(RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
                device_io_reply: Self::response(request, if exists_dir && must_be_file { NtStatus::NOT_A_DIRECTORY } else { NtStatus::NO_SUCH_FILE }), file_id: 0, information: Information::empty(),
            }))]);
        }
        let directory = wants_directory || exists_dir || path.is_empty();
        if !exists {
            if directory { self.drive.create_dir(path.clone()); } else { self.drive.create_file(path.clone()); }
        } else if !directory && matches!(req.create_disposition, CreateDisposition::FILE_OVERWRITE | CreateDisposition::FILE_OVERWRITE_IF | CreateDisposition::FILE_SUPERSEDE) {
            let file = self.drive.create_file(path.clone());
            file.size = 0;
            file.data = Some(Vec::new());
            file.last_modified = VIRTUAL_DRIVE_FILETIME;
        }
        let file_id = self.allocate_file_id();
        self.handles.insert(file_id, OpenHandle { path, directory, children: None, written: false });
        self.proxy.send_diagnostic(format!("create id={file_id} path={} status=SUCCESS directory={directory}", req.path));
        Ok(vec![SvcMessage::from(RdpdrPdu::DeviceCreateResponse(DeviceCreateResponse {
            device_io_reply: Self::response(request, NtStatus::SUCCESS), file_id,
            information: if exists { Information::FILE_OPENED } else { Information::FILE_CREATED },
        }))])
    }

    fn read(&mut self, req: DeviceReadRequest) -> Vec<SvcMessage> {
        let path = self.handles.get(&req.device_io_request.file_id)
            .and_then(|handle| (!handle.directory).then_some(handle.path.as_str()))
            .map(str::to_owned);
        let data = path.as_deref().and_then(|path| self.drive.file_data(path))
            .map(|data| {
                let start = usize::try_from(req.offset).unwrap_or(usize::MAX).min(data.len());
                let len = usize::try_from(req.length).unwrap_or(0);
                data[start..start.saturating_add(len).min(data.len())].to_vec()
            });
        if let Some(data) = data {
            return vec![SvcMessage::from(RdpdrPdu::DeviceReadResponse(DeviceReadResponse { device_io_reply: Self::response(req.device_io_request, NtStatus::SUCCESS), read_data: data }))];
        }
        let Some(name) = path.filter(|path| self.drive.file_size(path).is_some()) else {
            return vec![SvcMessage::from(RdpdrPdu::DeviceReadResponse(DeviceReadResponse { device_io_reply: Self::response(req.device_io_request, NtStatus::NO_SUCH_FILE), read_data: Vec::new() }))];
        };
        let request_id = self.next_read_request_id;
        self.next_read_request_id = self.next_read_request_id.wrapping_add(1).max(1);
        let offset = req.offset;
        let length = req.length;
        self.pending_reads.insert(request_id, req);
        self.proxy.send_read_requested(request_id, name, offset, length);
        Vec::new()
    }

    pub(crate) fn complete_read(&mut self, request_id: u32, data: Vec<u8>, failed: bool) -> Vec<SvcMessage> {
        let Some(req) = self.pending_reads.remove(&request_id) else {
            self.proxy.send_diagnostic(format!("[DEBUG-rdpdrive-response] read id={request_id} status=dropped reason=unknown-request"));
            return Vec::new();
        };
        let status = if failed { NtStatus::UNSUCCESSFUL } else { NtStatus::SUCCESS };
        self.proxy.send_diagnostic(format!(
            "[DEBUG-rdpdrive-response] read id={request_id} completion={} path={} status={status:?} bytes={}",
            req.device_io_request.completion_id,
            self.handles.get(&req.device_io_request.file_id).map_or("<missing>", |handle| handle.path.as_str()),
            data.len(),
        ));
        vec![SvcMessage::from(RdpdrPdu::DeviceReadResponse(DeviceReadResponse { device_io_reply: Self::response(req.device_io_request, status), read_data: if failed { Vec::new() } else { data } }))]
    }

    fn write(&mut self, req: DeviceWriteRequest) -> Vec<SvcMessage> {
        let request = req.device_io_request;
        let bytes = req.write_data;
        let path = self.handles.get_mut(&request.file_id).and_then(|handle| {
            if handle.directory { None } else { handle.written = true; Some(handle.path.clone()) }
        });
        let status = if let Some(path) = path {
            let file = self.drive.create_file(path);
            let data = file.data.get_or_insert_with(Vec::new);
            let start = usize::try_from(req.offset).unwrap_or(usize::MAX);
            if start <= data.len() {
                let end = start.saturating_add(bytes.len());
                if end > data.len() { data.resize(end, 0); }
                data[start..end].copy_from_slice(&bytes);
                file.size = u64::try_from(data.len()).unwrap_or(u64::MAX);
                file.last_modified = VIRTUAL_DRIVE_FILETIME;
                NtStatus::SUCCESS
            } else { NtStatus::UNSUCCESSFUL }
        } else { NtStatus::NO_SUCH_FILE };
        let length = if status == NtStatus::SUCCESS { u32::try_from(bytes.len()).unwrap_or(0) } else { 0 };
        vec![SvcMessage::from(RdpdrPdu::DeviceWriteResponse(DeviceWriteResponse { device_io_reply: Self::response(request, status), length }))]
    }

    fn directory(&mut self, req: ServerDriveQueryDirectoryRequest) -> Vec<SvcMessage> {
        let request = req.device_io_request;
        let Some(handle) = self.handles.get_mut(&request.file_id) else { return Self::directory_response(request, NtStatus::NO_SUCH_FILE, None); };
        if !handle.directory { return Self::directory_response(request, NtStatus::NOT_A_DIRECTORY, None); }
        if req.initial_query != 0 {
            let Ok(path) = self.drive.directory_query_path(&handle.path, &req.path) else {
                self.proxy.send_diagnostic(format!("directory id={} path={} status=ACCESS_DENIED", request.file_id, req.path));
                return Self::directory_response(request, NtStatus::ACCESS_DENIED, None);
            };
            handle.children = Some(self.drive.children(&path));
            // A query path selects an enumeration target, not a new identity
            // for the directory handle. Explorer may enumerate a child using
            // a parent handle and then reuse that parent for another query or
            // an open. Retargeting the handle made those later requests refer
            // to the wrong virtual path.
            self.proxy.send_diagnostic(format!("directory id={} requested={} target={path} entries={}", request.file_id, req.path, handle.children.as_ref().map_or(0, Vec::len)));
        }
        let entry = handle.children.as_mut().and_then(|entries| if entries.is_empty() { None } else { Some(entries.remove(0)) });
        match entry {
            Some((name, directory, size, last_modified)) => {
                self.proxy.send_diagnostic(format!("directory id={} status=SUCCESS entry={name} directory={directory}", request.file_id));
                Self::directory_response(request, NtStatus::SUCCESS, Some(Self::directory_info(req.file_info_class_lvl, name, directory, size, last_modified)))
            }
            None => {
                let status = if req.initial_query != 0 { NtStatus::NO_SUCH_FILE } else { NtStatus::NO_MORE_FILES };
                self.proxy.send_diagnostic(format!("directory id={} status={status:?}", request.file_id));
                Self::directory_response(request, status, None)
            }
        }
    }

    fn directory_info(level: FileInformationClassLevel, name: String, directory: bool, size: usize, last_modified: i64) -> FileInformationClass {
        let attributes = if directory { FileAttributes::FILE_ATTRIBUTE_DIRECTORY } else { FileAttributes::FILE_ATTRIBUTE_ARCHIVE };
        let size = i64::try_from(size).unwrap_or(i64::MAX);
        match level {
            FileInformationClassLevel::FILE_DIRECTORY_INFORMATION => FileDirectoryInformation::new(last_modified, last_modified, last_modified, last_modified, size, attributes, name).into(),
            FileInformationClassLevel::FILE_FULL_DIRECTORY_INFORMATION => FileFullDirectoryInformation::new(last_modified, last_modified, last_modified, last_modified, size, attributes, name).into(),
            FileInformationClassLevel::FILE_NAMES_INFORMATION => FileNamesInformation::new(name).into(),
            _ => FileBothDirectoryInformation::new(last_modified, last_modified, last_modified, last_modified, size, attributes, name).into(),
        }
    }

    fn directory_response(request: ironrdp::rdpdr::pdu::efs::DeviceIoRequest, status: NtStatus, buffer: Option<FileInformationClass>) -> Vec<SvcMessage> {
        vec![SvcMessage::from(RdpdrPdu::ClientDriveQueryDirectoryResponse(ClientDriveQueryDirectoryResponse { device_io_reply: Self::response(request, status), buffer }))]
    }

    fn update_open_handle_paths(&mut self, from: &str, to: &str) {
        let prefix = format!("{from}/");
        for handle in self.handles.values_mut() {
            if handle.path == from {
                handle.path = to.to_owned();
            } else if let Some(suffix) = handle.path.strip_prefix(&prefix) {
                handle.path = format!("{to}/{suffix}");
            }
        }
    }
}

impl RdpdrBackend for WasmDriveBackend {
    fn handle_server_device_announce_response(&mut self, pdu: ServerDeviceAnnounceResponse) -> PduResult<()> {
        if pdu.result_code == NtStatus::SUCCESS { debug!(device_id = pdu.device_id, "RDPDR browser drive announced"); }
        else { warn!(device_id = pdu.device_id, status = ?pdu.result_code, "RDPDR browser drive rejected"); }
        Ok(())
    }
    fn handle_scard_call(&mut self, _req: DeviceControlRequest<ScardIoCtlCode>, _call: ScardCall) -> PduResult<Vec<SvcMessage>> { Ok(Vec::new()) }
    fn handle_drive_io_request(&mut self, req: ServerDriveIoRequest) -> PduResult<Vec<SvcMessage>> {
        let request_kind = match &req {
            ServerDriveIoRequest::ServerCreateDriveRequest(_) => "create",
            ServerDriveIoRequest::DeviceReadRequest(_) => "read",
            ServerDriveIoRequest::DeviceWriteRequest(_) => "write",
            ServerDriveIoRequest::DeviceCloseRequest(_) => "close",
            ServerDriveIoRequest::DeviceFlushBuffersRequest(_) => "flush",
            ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(_) => "query-directory",
            ServerDriveIoRequest::ServerDriveQueryInformationRequest(_) => "query-information",
            ServerDriveIoRequest::ServerDriveQueryVolumeInformationRequest(_) => "query-volume",
            ServerDriveIoRequest::ServerDriveSetInformationRequest(_) => "set-information",
            ServerDriveIoRequest::DeviceControlRequest(_) => "device-control",
            ServerDriveIoRequest::ServerDriveQuerySecurityRequest(_) => "query-security",
            ServerDriveIoRequest::ServerDriveSetSecurityRequest(_) => "set-security",
            ServerDriveIoRequest::ServerDriveNotifyChangeDirectoryRequest(_) => "notify-directory",
            ServerDriveIoRequest::ServerDriveLockControlRequest(_) => "lock-control",
        };
        self.proxy.send_diagnostic(format!("[DEBUG-rdpdrive-dispatch] request={request_kind}"));
        Ok(match req {
            ServerDriveIoRequest::ServerCreateDriveRequest(req) => self.create(req)?,
            ServerDriveIoRequest::DeviceReadRequest(req) => self.read(req),
            ServerDriveIoRequest::DeviceWriteRequest(req) => self.write(req),
            ServerDriveIoRequest::DeviceCloseRequest(req) => {
                if let Some(handle) = self.handles.remove(&req.device_io_request.file_id) {
                    if handle.written && !handle.directory {
                if let Some(data) = self.drive.file_data(&handle.path) {
                            self.proxy.send_completed(handle.path, data.to_vec());
                        }
                    }
                }
                vec![SvcMessage::from(RdpdrPdu::DeviceCloseResponse(DeviceCloseResponse { device_io_response: Self::response(req.device_io_request, NtStatus::SUCCESS) }))]
            }
            ServerDriveIoRequest::DeviceFlushBuffersRequest(req) => vec![SvcMessage::from(RdpdrPdu::DeviceFlushBuffersResponse(DeviceFlushBuffersResponse { device_io_response: Self::response(req.device_io_request, NtStatus::SUCCESS) }))],
            ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(req) => self.directory(req),
            ServerDriveIoRequest::ServerDriveQueryInformationRequest(req) => {
                let entry = self.handles.get(&req.device_io_request.file_id).and_then(|handle| self.drive.metadata(&handle.path));
                let (status, buffer) = match entry {
                    Some((directory, size, last_modified)) => {
                        let attributes = if directory { FileAttributes::FILE_ATTRIBUTE_DIRECTORY } else { FileAttributes::FILE_ATTRIBUTE_ARCHIVE };
                        let size = i64::try_from(size).unwrap_or(i64::MAX);
                        let info = match req.file_info_class_lvl {
                            FileInformationClassLevel::FILE_BASIC_INFORMATION => Some(FileBasicInformation { creation_time: last_modified, last_access_time: last_modified, last_write_time: last_modified, change_time: last_modified, file_attributes: attributes }.into()),
                            FileInformationClassLevel::FILE_STANDARD_INFORMATION => Some(FileStandardInformation { allocation_size: size, end_of_file: size, number_of_links: 1, delete_pending: Boolean::False, directory: if directory { Boolean::True } else { Boolean::False } }.into()),
                            FileInformationClassLevel::FILE_ATTRIBUTE_TAG_INFORMATION => Some(FileAttributeTagInformation { file_attributes: attributes, reparse_tag: 0 }.into()),
                            _ => None,
                        };
                        (if info.is_some() { NtStatus::SUCCESS } else { NtStatus::NOT_SUPPORTED }, info)
                    }
                    None => (NtStatus::NO_SUCH_FILE, None),
                };
                self.proxy.send_diagnostic(format!("query-information id={} path={} class={:?} status={status:?}", req.device_io_request.file_id, self.handles.get(&req.device_io_request.file_id).map_or("<missing>", |handle| handle.path.as_str()), req.file_info_class_lvl));
                vec![SvcMessage::from(RdpdrPdu::ClientDriveQueryInformationResponse(ClientDriveQueryInformationResponse { device_io_response: Self::response(req.device_io_request, status), buffer }))]
            }
            ServerDriveIoRequest::ServerDriveQueryVolumeInformationRequest(req) => {
                let info = match req.fs_info_class_lvl {
                    FileSystemInformationClassLevel::FILE_FS_ATTRIBUTE_INFORMATION => Some(FileSystemInformationClass::FileFsAttributeInformation(FileFsAttributeInformation { file_system_attributes: FileSystemAttributes::FILE_CASE_PRESERVED_NAMES | FileSystemAttributes::FILE_UNICODE_ON_DISK, max_component_name_len: 255, file_system_name: "StoneVeyl".to_owned() })),
                    FileSystemInformationClassLevel::FILE_FS_SIZE_INFORMATION => Some(FileSystemInformationClass::FileFsSizeInformation(FileFsSizeInformation { total_alloc_units: 262_144, available_alloc_units: 262_144, sectors_per_alloc_unit: 1, bytes_per_sector: 4096 })),
                    FileSystemInformationClassLevel::FILE_FS_FULL_SIZE_INFORMATION => Some(FileSystemInformationClass::FileFsFullSizeInformation(FileFsFullSizeInformation { total_alloc_units: 262_144, caller_available_alloc_units: 262_144, actual_available_alloc_units: 262_144, sectors_per_alloc_unit: 1, bytes_per_sector: 4096 })),
                    FileSystemInformationClassLevel::FILE_FS_VOLUME_INFORMATION => Some(FileSystemInformationClass::FileFsVolumeInformation(FileFsVolumeInformation { volume_creation_time: VIRTUAL_DRIVE_FILETIME, volume_serial_number: 0x5356_4452, supports_objects: Boolean::False, volume_label: "StoneVeyl Files".to_owned() })),
                    _ => None,
                };
                let status = if info.is_some() { NtStatus::SUCCESS } else { NtStatus::NOT_SUPPORTED };
                vec![SvcMessage::from(RdpdrPdu::ClientDriveQueryVolumeInformationResponse(ClientDriveQueryVolumeInformationResponse { device_io_reply: Self::response(req.device_io_request, status), buffer: info }))]
            }
            ServerDriveIoRequest::ServerDriveSetInformationRequest(req) => {
                let handle_path = self.handles.get(&req.device_io_request.file_id).map(|handle| handle.path.clone());
                let status = if let Some(from) = handle_path {
                    match &req.set_buffer {
                        FileInformationClass::Rename(rename) => match VirtualDrive::normalize(&rename.file_name) {
                            Ok(to) => {
                                if self.drive.rename(&from, to.clone()) {
                                    self.update_open_handle_paths(&from, &to);
                                    NtStatus::SUCCESS
                                } else { NtStatus::UNSUCCESSFUL }
                            }
                            Err(()) => NtStatus::UNSUCCESSFUL,
                        },
                        FileInformationClass::Disposition(_) => { self.drive.remove(&from); NtStatus::SUCCESS },
                        _ => NtStatus::SUCCESS,
                    }
                } else { NtStatus::NO_SUCH_FILE };
                vec![SvcMessage::from(RdpdrPdu::ClientDriveSetInformationResponse(ClientDriveSetInformationResponse::new(&req, status).map_err(|error| encode_err!(error))?))]
            }
            ServerDriveIoRequest::DeviceControlRequest(req) => vec![SvcMessage::from(RdpdrPdu::DeviceControlResponse(DeviceControlResponse { device_io_reply: Self::response(req.header, NtStatus::SUCCESS), output_buffer: None }))],
            ServerDriveIoRequest::ServerDriveQuerySecurityRequest(req) => vec![SvcMessage::from(RdpdrPdu::ClientDriveQuerySecurityResponse(ClientDriveQuerySecurityResponse { device_io_response: Self::response(req.device_io_request, NtStatus::NOT_SUPPORTED), security_descriptor: None }))],
            ServerDriveIoRequest::ServerDriveSetSecurityRequest(req) => vec![SvcMessage::from(RdpdrPdu::ClientDriveSetSecurityResponse(ClientDriveSetSecurityResponse::new(&req, NtStatus::NOT_SUPPORTED).map_err(|error| encode_err!(error))?))],
            ServerDriveIoRequest::ServerDriveNotifyChangeDirectoryRequest(req) => vec![SvcMessage::from(
                RdpdrPdu::ClientDriveNotifyChangeDirectoryResponse(ClientDriveNotifyChangeDirectoryResponse::new(
                    req.device_io_request, NtStatus::NOT_SUPPORTED, Vec::new(),
                )),
            )],
            ServerDriveIoRequest::ServerDriveLockControlRequest(req) => vec![SvcMessage::from(
                RdpdrPdu::ClientDriveLockControlResponse(ClientDriveLockControlResponse::new(
                    req.device_io_request, NtStatus::NOT_SUPPORTED,
                )),
            )],
        })
    }
}

/// One RDPDR processor services both the selected browser drive and the
/// optional PDF printer. The protocol sends filesystem and printer IRPs down
/// separate paths, so this small router preserves the existing printer while
/// allowing a drive to be announced in the same session.
#[derive(Debug)]
pub(crate) struct WasmRdpdrBackend {
    drive: Option<WasmDriveBackend>,
    printer: Option<crate::printer::WasmPrinterBackend>,
    deferred_messages: Vec<SvcMessage>,
}

impl_as_any!(WasmRdpdrBackend);

impl WasmRdpdrBackend {
    pub(crate) fn new(
        drive: Option<WasmDriveBackend>,
        printer: Option<crate::printer::WasmPrinterBackend>,
    ) -> Option<Self> {
        if drive.is_none() && printer.is_none() { None } else { Some(Self { drive, printer, deferred_messages: Vec::new() }) }
    }

    pub(crate) fn has_drive(&self) -> bool { self.drive.is_some() }
    pub(crate) fn has_printer(&self) -> bool { self.printer.is_some() }
    pub(crate) fn complete_drive_read(&mut self, request_id: u32, data: Vec<u8>, failed: bool) -> bool {
        let messages = self.drive.as_mut().map_or_else(Vec::new, |drive| drive.complete_read(request_id, data, failed));
        let queued = !messages.is_empty();
        self.deferred_messages.extend(messages);
        queued
    }

    pub(crate) fn poll_deferred_messages(&mut self) -> Vec<SvcMessage> {
        core::mem::take(&mut self.deferred_messages)
    }
}

impl RdpdrBackend for WasmRdpdrBackend {
    fn handle_server_device_announce_response(&mut self, pdu: ServerDeviceAnnounceResponse) -> PduResult<()> {
        if let Some(drive) = &mut self.drive { drive.handle_server_device_announce_response(pdu.clone())?; }
        if let Some(printer) = &mut self.printer { printer.handle_server_device_announce_response(pdu)?; }
        Ok(())
    }

    fn handle_scard_call(&mut self, req: DeviceControlRequest<ScardIoCtlCode>, call: ScardCall) -> PduResult<Vec<SvcMessage>> {
        if let Some(printer) = &mut self.printer { printer.handle_scard_call(req, call) } else { Ok(Vec::new()) }
    }

    fn handle_drive_io_request(&mut self, req: ServerDriveIoRequest) -> PduResult<Vec<SvcMessage>> {
        if let Some(drive) = &mut self.drive { drive.handle_drive_io_request(req) } else { Ok(Vec::new()) }
    }

    fn handle_printer_io_request(&mut self, req: PrinterIoRequest) -> PduResult<Vec<SvcMessage>> {
        if let Some(printer) = &mut self.printer { printer.handle_printer_io_request(req) }
        else { Ok(Vec::new()) }
    }

    fn reject_printer_write(&mut self, req: ironrdp::rdpdr::pdu::efs::DeviceIoRequest) -> PduResult<Vec<SvcMessage>> {
        if let Some(printer) = &mut self.printer { printer.reject_printer_write(req) } else { Ok(Vec::new()) }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confines_paths_and_enumerates_immediate_children() {
        assert!(VirtualDrive::normalize("../secret").is_err());
        let drive = VirtualDrive::from_seed_files(vec![
            DriveSeedFile { name: "notes/readme.txt".to_owned(), size: 2, last_modified: 1_704_067_200_000 },
            DriveSeedFile { name: "top.txt".to_owned(), size: 3, last_modified: 1_704_067_200_000 },
        ]);
        assert!(drive.is_dir("notes"));
        assert_eq!(drive.file_size("notes/readme.txt"), Some(2));
        assert_eq!(drive.file_data("notes/readme.txt"), None);
        assert_eq!(drive.children(""), vec![("notes".to_owned(), true, 0, VIRTUAL_DRIVE_FILETIME), ("top.txt".to_owned(), false, 3, filetime_from_unix_millis(1_704_067_200_000))]);
    }

    #[test]
    fn renaming_a_directory_keeps_its_children_reachable() {
        let mut drive = VirtualDrive::from_seed_files(vec![
            DriveSeedFile { name: "incoming/nested/readme.txt".to_owned(), size: 2, last_modified: 1_704_067_200_000 },
        ]);
        assert!(drive.rename("incoming", "archive".to_owned()));
        assert!(!drive.is_dir("incoming"));
        assert!(drive.is_dir("archive/nested"));
        assert_eq!(drive.file_size("archive/nested/readme.txt"), Some(2));
    }

    #[test]
    fn directory_wildcard_keeps_the_open_nested_directory_path() {
        let drive = VirtualDrive::from_seed_files(vec![
            DriveSeedFile { name: "Grandstream/9.127/readme.txt".to_owned(), size: 2, last_modified: 1_704_067_200_000 },
        ]);
        assert_eq!(
            drive.directory_query_path("Grandstream/9.127", "*"),
            Ok("Grandstream/9.127".to_owned())
        );
        assert_eq!(
            drive.directory_query_path("Grandstream/9.127", "\\*"),
            Ok("Grandstream/9.127".to_owned())
        );
        assert_eq!(
            drive.directory_query_path("Grandstream", "9.127\\*"),
            Ok("Grandstream/9.127".to_owned())
        );
    }

    #[test]
    fn child_enumeration_does_not_retarget_its_open_parent_handle() {
        let drive = VirtualDrive::from_seed_files(vec![
            DriveSeedFile { name: "Grandstream/9.127/readme.txt".to_owned(), size: 2, last_modified: 1_704_067_200_000 },
            DriveSeedFile { name: "Grandstream/11.110/notes.txt".to_owned(), size: 3, last_modified: 1_704_067_200_000 },
        ]);
        let mut handle = OpenHandle { path: "Grandstream".to_owned(), directory: true, children: None, written: false };
        let target = drive.directory_query_path(&handle.path, "9.127\\*").expect("relative child query");
        handle.children = Some(drive.children(&target));

        assert_eq!(target, "Grandstream/9.127");
        assert_eq!(handle.path, "Grandstream", "enumeration must not retarget the opened directory");
        assert_eq!(handle.children, Some(vec![("readme.txt".to_owned(), false, 2, filetime_from_unix_millis(1_704_067_200_000))]));
    }

    #[test]
    fn directory_entries_expose_valid_filetimes() {
        let info = WasmDriveBackend::directory_info(
            FileInformationClassLevel::FILE_BOTH_DIRECTORY_INFORMATION,
            "9.127".to_owned(),
            true,
            0,
            VIRTUAL_DRIVE_FILETIME,
        );
        let FileInformationClass::BothDirectory(info) = info else {
            panic!("expected FILE_BOTH_DIRECTORY_INFORMATION");
        };
        assert_eq!(info.creation_time, VIRTUAL_DRIVE_FILETIME);
        assert_eq!(info.last_access_time, VIRTUAL_DRIVE_FILETIME);
        assert_eq!(info.last_write_time, VIRTUAL_DRIVE_FILETIME);
        assert_eq!(info.change_time, VIRTUAL_DRIVE_FILETIME);
        assert!(info.file_attributes.contains(FileAttributes::FILE_ATTRIBUTE_DIRECTORY));
    }
}
