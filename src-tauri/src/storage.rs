//! Durable replacement and publish-after-save transactions for JSON stores.

use std::path::Path;
use serde::Serialize;

pub fn save(path: &Path, value: &impl Serialize) -> Result<(), String> {
    use std::io::Write;
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| format!("Ошибка сериализации: {e}"))?;
    let parent = path.parent().ok_or("Не найдена папка хранилища")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("Не удалось создать папку: {e}"))?;
    let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(|e| format!("Не удалось сохранить данные: {e}"))
}

#[cfg(not(windows))]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::rename(from, to)
}

#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    // REPLACE_EXISTING | WRITE_THROUGH keeps the previous file if replacement fails.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0x1 | 0x8) } == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn transaction<T: Clone, R>(
    current: &mut T,
    change: impl FnOnce(&mut T) -> Result<R, String>,
    persist: impl FnOnce(&T) -> Result<(), String>,
) -> Result<R, String> {
    let mut next = current.clone();
    let result = change(&mut next)?;
    persist(&next)?;
    *current = next;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_save_or_change_does_not_publish() {
        let mut value = vec![1];
        assert!(transaction(&mut value, |v| { v.push(2); Ok(()) }, |_| Err("disk".into())).is_err());
        assert_eq!(value, [1]);
        assert!(transaction(&mut value, |v| { v.push(3); Err::<(), _>("change".into()) }, |_| Ok(())).is_err());
        assert_eq!(value, [1]);
        transaction(&mut value, |v| { v.push(4); Ok(()) }, |_| Ok(())).unwrap();
        assert_eq!(value, [1, 4]);
    }

    #[test]
    fn replaces_existing_file_and_keeps_it_on_failure() {
        let dir = std::env::temp_dir().join(format!("ttcm-store-{}", uuid::Uuid::new_v4()));
        let path = dir.join("store.json");
        save(&path, &vec![1]).unwrap();
        save(&path, &vec![2]).unwrap();
        assert_eq!(serde_json::from_slice::<Vec<i32>>(&std::fs::read(&path).unwrap()).unwrap(), [2]);
        assert!(save(&path.join("impossible.json"), &vec![3]).is_err());
        assert_eq!(serde_json::from_slice::<Vec<i32>>(&std::fs::read(&path).unwrap()).unwrap(), [2]);
        let occupied = dir.join("occupied");
        std::fs::create_dir(&occupied).unwrap();
        std::fs::write(occupied.join("keep"), b"old").unwrap();
        assert!(save(&occupied, &vec![4]).is_err());
        assert_eq!(std::fs::read(occupied.join("keep")).unwrap(), b"old");
        assert!(!std::fs::read_dir(&dir).unwrap().flatten().any(|e| e.path().extension().is_some_and(|ext| ext == "tmp")));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
