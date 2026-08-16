from pathlib import Path

path = Path("src/dbus/manager_iface.rs")
text = path.read_text(encoding="utf-8")

old_virtualization = '''        } else {
            Default::default()
        }
    }

    /// Confidential virtualization'''
new_virtualization = '''        } else {
            String::default()
        }
    }

    /// Confidential virtualization'''
if text.count(old_virtualization) != 1:
    raise SystemExit(f"virtualization String default matches: {text.count(old_virtualization)}")
text = text.replace(old_virtualization, new_virtualization, 1)

old_cgroup = '''            if path != "/" {
                path.to_owned()
            } else {
                Default::default()
            }
        })'''
new_cgroup = '''            if path != "/" {
                path.to_owned()
            } else {
                String::default()
            }
        })'''
if text.count(old_cgroup) != 1:
    raise SystemExit(f"cgroup String default matches: {text.count(old_cgroup)}")
text = text.replace(old_cgroup, new_cgroup, 1)

path.write_text(text, encoding="utf-8")
