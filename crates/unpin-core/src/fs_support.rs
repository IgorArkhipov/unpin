use std::{
    fs::{self, ReadDir},
    io,
    path::Path,
};

pub(crate) fn read_optional_string(path: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn read_optional_dir(path: &Path) -> io::Result<Option<ReadDir>> {
    match fs::read_dir(path) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
pub(crate) fn path_matches_open_file(path: &Path, file: &fs::File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;

    let file_metadata = file.metadata()?;
    let current_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(current_metadata.file_type().is_file()
        && current_metadata.dev() == file_metadata.dev()
        && current_metadata.ino() == file_metadata.ino())
}

#[cfg(windows)]
pub(crate) fn path_matches_open_file(path: &Path, file: &fs::File) -> io::Result<bool> {
    let path_identity = match windows_path_identity_without_reparse_follow(path) {
        Ok(identity) => identity,
        Err(error) if windows_path_no_longer_names_file(&error) => return Ok(false),
        // Access and sharing errors do not prove that the path changed, so
        // preserve them as I/O failures instead of reporting a mismatch.
        Err(error) => return Err(error),
    };
    let file_identity = windows_file_identity(file)?;
    Ok(windows_identity_values_match(
        path_identity
            .full_file_id
            .then_some((path_identity.volume, path_identity.file_id)),
        (path_identity.legacy_volume, path_identity.legacy_file_index),
        file_identity
            .full_file_id
            .then_some((file_identity.volume, file_identity.file_id)),
        (file_identity.legacy_volume, file_identity.legacy_file_index),
    ))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn path_matches_open_file(_path: &Path, _file: &fs::File) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable file identity is unavailable on this platform",
    ))
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct WindowsFileIdentity {
    pub(crate) volume: u64,
    pub(crate) file_id: [u8; 16],
    pub(crate) full_file_id: bool,
    pub(crate) legacy_volume: u32,
    pub(crate) legacy_file_index: u64,
    pub(crate) workspace_reliable: bool,
}

#[cfg(windows)]
impl PartialEq for WindowsFileIdentity {
    fn eq(&self, other: &Self) -> bool {
        windows_identity_values_match(
            self.full_file_id.then_some((self.volume, self.file_id)),
            (self.legacy_volume, self.legacy_file_index),
            other.full_file_id.then_some((other.volume, other.file_id)),
            (other.legacy_volume, other.legacy_file_index),
        )
    }
}

#[cfg(windows)]
impl Eq for WindowsFileIdentity {}

#[cfg(windows)]
pub(crate) fn windows_path_identity(path: &Path) -> io::Result<WindowsFileIdentity> {
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    windows_path_identity_with_flags(path, FILE_FLAG_BACKUP_SEMANTICS)
}

#[cfg(windows)]
fn windows_path_identity_without_reparse_follow(path: &Path) -> io::Result<WindowsFileIdentity> {
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    windows_path_identity_with_flags(
        path,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
}

#[cfg(windows)]
fn windows_path_identity_with_flags(
    path: &Path,
    custom_flags: u32,
) -> io::Result<WindowsFileIdentity> {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};

    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;

    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(custom_flags)
        .open(path)?;
    windows_file_identity(&file)
}

#[cfg(windows)]
pub(crate) fn windows_file_identity(file: &fs::File) -> io::Result<WindowsFileIdentity> {
    use std::{ffi::c_void, mem::MaybeUninit, os::windows::io::AsRawHandle};

    #[repr(C)]
    struct FileId128 {
        identifier: [u8; 16],
    }

    #[repr(C)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: FileId128,
    }

    const _: () = assert!(std::mem::size_of::<FileIdInfo>() == 24);

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileInformationByHandleEx"]
        fn get_file_information_by_handle_ex(
            file: *mut c_void,
            information_class: i32,
            information: *mut c_void,
            buffer_size: u32,
        ) -> i32;
    }

    const FILE_ID_INFO_CLASS: i32 = 18;

    let mut information = MaybeUninit::<FileIdInfo>::uninit();
    let buffer_size = u32::try_from(std::mem::size_of::<FileIdInfo>())
        .expect("validated FILE_ID_INFO size fits in u32");
    // SAFETY: `file` owns a valid handle for the duration of this call, and
    // `information` points to writable storage for the exact Windows ABI type.
    let succeeded = unsafe {
        get_file_information_by_handle_ex(
            file.as_raw_handle(),
            FILE_ID_INFO_CLASS,
            information.as_mut_ptr().cast(),
            buffer_size,
        )
    };
    if succeeded == 0 {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(1 | 50 | 87)) {
            let (legacy_volume, legacy_file_index) = windows_legacy_file_identity(file)?;
            return Ok(WindowsFileIdentity {
                volume: u64::from(legacy_volume),
                file_id: encode_legacy_windows_file_id(legacy_file_index),
                full_file_id: false,
                legacy_volume,
                legacy_file_index,
                workspace_reliable: false,
            });
        }
        return Err(error);
    }
    // SAFETY: a successful `GetFileInformationByHandleEx` call initializes the
    // complete `FileIdInfo` value.
    let information = unsafe { information.assume_init() };
    let (legacy_volume, legacy_file_index) = windows_legacy_file_identity(file)?;
    // The legacy API exposes only a 32-bit volume serial representation, so
    // compare the file-ID relation without treating the volume widths as equal.
    let workspace_reliable =
        information.file_id.identifier == encode_legacy_windows_file_id(legacy_file_index);
    Ok(WindowsFileIdentity {
        volume: information.volume_serial_number,
        file_id: information.file_id.identifier,
        full_file_id: true,
        legacy_volume,
        legacy_file_index,
        workspace_reliable,
    })
}

#[cfg(windows)]
fn windows_legacy_file_identity(file: &fs::File) -> io::Result<(u32, u64)> {
    use std::{ffi::c_void, mem::MaybeUninit, os::windows::io::AsRawHandle};

    #[repr(C)]
    #[allow(dead_code)]
    struct FileTime {
        low_date_time: u32,
        high_date_time: u32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        #[link_name = "GetFileInformationByHandle"]
        fn get_file_information_by_handle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = MaybeUninit::<ByHandleFileInformation>::uninit();
    // SAFETY: `file` owns a valid handle for the duration of this call, and
    // `information` points to writable storage for the exact Windows ABI type.
    let succeeded =
        unsafe { get_file_information_by_handle(file.as_raw_handle(), information.as_mut_ptr()) };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `GetFileInformationByHandle` call initializes the
    // complete `ByHandleFileInformation` value.
    let information = unsafe { information.assume_init() };
    let index =
        (u64::from(information.file_index_high) << 32) | u64::from(information.file_index_low);
    Ok((information.volume_serial_number, index))
}

#[cfg(any(windows, test))]
fn encode_legacy_windows_file_id(index: u64) -> [u8; 16] {
    let mut file_id = [0; 16];
    file_id[..8].copy_from_slice(&index.to_le_bytes());
    file_id
}

#[cfg(any(windows, test))]
fn windows_identity_values_match(
    left_full: Option<(u64, [u8; 16])>,
    left_legacy: (u32, u64),
    right_full: Option<(u64, [u8; 16])>,
    right_legacy: (u32, u64),
) -> bool {
    match (left_full, right_full) {
        (Some(left), Some(right)) => left == right,
        (None, None) => left_legacy == right_legacy,
        _ => false,
    }
}

#[cfg(any(windows, test))]
fn windows_path_no_longer_names_file(error: &io::Error) -> bool {
    const ERROR_DELETE_PENDING: i32 = 303;

    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(ERROR_DELETE_PENDING)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_paths_are_optional() {
        let root = tempfile::TempDir::new().expect("temp root");
        assert!(
            read_optional_string(&root.path().join("missing"))
                .unwrap()
                .is_none()
        );
        assert!(
            read_optional_dir(&root.path().join("missing"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn legacy_windows_file_id_uses_file_id_128_byte_layout() {
        assert_eq!(
            encode_legacy_windows_file_id(0x0102_0304_0506_0708),
            [
                0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn windows_identity_comparison_uses_one_consistent_identity_width() {
        let full_id = [7; 16];
        assert!(windows_identity_values_match(
            Some((11, full_id)),
            (1, 2),
            Some((11, full_id)),
            (3, 4),
        ));
        assert!(windows_identity_values_match(None, (5, 6), None, (5, 6),));
        assert!(!windows_identity_values_match(None, (5, 6), None, (5, 7),));
        assert!(!windows_identity_values_match(
            Some((11, full_id)),
            (5, 6),
            None,
            (5, 6),
        ));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn open_file_identity_rejects_a_replaced_path() {
        let root = tempfile::TempDir::new().expect("temp root");
        let current_path = root.path().join("current");
        let retained_path = root.path().join("retained");
        fs::write(&current_path, "original").expect("original file");

        let opened_file = fs::File::open(&current_path).expect("open original");
        assert!(path_matches_open_file(&current_path, &opened_file).expect("matching original"));

        fs::rename(&current_path, &retained_path).expect("retain original");
        assert!(
            !path_matches_open_file(&current_path, &opened_file)
                .expect("missing path is a mismatch")
        );
        fs::write(&current_path, "replacement").expect("replacement file");
        assert!(!path_matches_open_file(&current_path, &opened_file).expect("compare replacement"));

        #[cfg(unix)]
        {
            fs::remove_file(&current_path).expect("remove replacement");
            std::os::unix::fs::symlink(&retained_path, &current_path)
                .expect("replace path with symlink");
            assert!(
                !path_matches_open_file(&current_path, &opened_file)
                    .expect("compare symlink replacement")
            );
        }
    }

    #[test]
    fn windows_delete_pending_is_a_path_mismatch_but_access_errors_are_not() {
        assert!(windows_path_no_longer_names_file(
            &io::Error::from_raw_os_error(303)
        ));
        assert!(windows_path_no_longer_names_file(&io::Error::from(
            io::ErrorKind::NotFound
        )));
        assert!(!windows_path_no_longer_names_file(
            &io::Error::from_raw_os_error(5)
        ));
        assert!(!windows_path_no_longer_names_file(
            &io::Error::from_raw_os_error(32)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lookup_errors_are_not_classified_as_missing() {
        use std::os::unix::fs::symlink;

        let root = tempfile::TempDir::new().expect("temp root");
        let loop_path = root.path().join("loop");
        symlink("loop", &loop_path).expect("create symlink loop");

        assert!(read_optional_string(&loop_path).is_err());
        assert!(read_optional_dir(&loop_path).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_matches_open_handles_and_distinguishes_files() {
        let root = tempfile::TempDir::new().expect("temp root");
        let first_path = root.path().join("first");
        let second_path = root.path().join("second");
        fs::write(&first_path, "first").expect("first file");
        fs::write(&second_path, "second").expect("second file");

        let first_file = fs::File::open(&first_path).expect("open first file");
        assert!(
            path_matches_open_file(&first_path, &first_file).expect("matching path and handle")
        );
        let first_path_identity = windows_path_identity(&first_path).expect("first path identity");
        let first_handle_identity =
            windows_file_identity(&first_file).expect("first handle identity");
        assert_eq!(first_path_identity, first_handle_identity);
        assert_eq!(
            first_path_identity.workspace_reliable,
            first_handle_identity.workspace_reliable
        );
        assert_ne!(
            windows_path_identity(&first_path).expect("first identity"),
            windows_path_identity(&second_path).expect("second identity")
        );
        windows_path_identity(root.path()).expect("directory identity");
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_does_not_follow_a_reparse_point() {
        use std::os::windows::fs::symlink_file;

        let root = tempfile::TempDir::new().expect("temp root");
        let current_path = root.path().join("current");
        let retained_path = root.path().join("retained");
        fs::write(&current_path, "original").expect("original file");
        let opened_file = fs::File::open(&current_path).expect("open original");
        fs::rename(&current_path, &retained_path).expect("retain original");
        match symlink_file(&retained_path, &current_path) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(1314) => return,
            Err(error) => panic!("create file symlink: {error}"),
        }
        assert!(
            !path_matches_open_file(&current_path, &opened_file).expect("compare reparse point")
        );
    }
}
