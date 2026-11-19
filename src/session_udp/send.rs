//! Pure policy of the send area of a UDP Session tab.
//!
//! The window asks this module what the Send button has to do and whether a
//! mode switch converts the editor buffer. The module knows no gpui and no
//! tokio: it is a decision function, not a widget.

/// What the Send button does for the current tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSend {
    /// Pass this trimmed name to the session machine.
    Command(String),
    /// Send the text or hex editor bytes as they are.
    Editor,
    /// Do not touch the write channel.
    Drop,
}

/// The decision of the Send button.
///
/// Command mode belongs to a UDP Session tab only; every other protocol and
/// every other mode sends the editor bytes.
pub fn session_send(is_udp_session: bool, mode: &str, ready: bool, field: &str) -> SessionSend {
    if !(is_udp_session && mode == "command") {
        return SessionSend::Editor;
    }
    if !ready {
        return SessionSend::Drop;
    }
    let name = field.trim();
    if name.is_empty() {
        SessionSend::Drop
    } else {
        SessionSend::Command(name.to_string())
    }
}

/// A named button sends only while the session is established.
pub fn command_click(ready: bool) -> bool {
    ready
}

/// Text and hex convert into each other. Command has its own field.
pub fn converts_editor_on_switch(from_mode: &str, to_mode: &str) -> bool {
    from_mode != to_mode && from_mode != "command" && to_mode != "command"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_mode_trims_the_field_and_refuses_a_blank_one() {
        assert!(matches!(
            session_send(true, "command", true, "  set_temperature  "),
            SessionSend::Command(name) if name == "set_temperature"
        ));
        assert!(matches!(
            session_send(true, "command", true, "   "),
            SessionSend::Drop
        ));
    }

    #[test]
    fn command_mode_sends_nothing_until_the_session_is_ready() {
        assert!(matches!(
            session_send(true, "command", false, "get_status"),
            SessionSend::Drop
        ));
        assert!(!command_click(false));
        assert!(command_click(true));
    }

    #[test]
    fn text_hex_and_other_protocols_keep_the_editor() {
        assert!(matches!(
            session_send(true, "text", true, "get_status"),
            SessionSend::Editor
        ));
        assert!(matches!(
            session_send(true, "hex", true, "aa"),
            SessionSend::Editor
        ));
        assert!(matches!(
            session_send(false, "command", true, "get_status"),
            SessionSend::Editor
        ));
    }

    #[test]
    fn command_mode_does_not_convert_the_editor_buffer() {
        assert!(!converts_editor_on_switch("text", "command"));
        assert!(!converts_editor_on_switch("command", "hex"));
        assert!(!converts_editor_on_switch("command", "command"));
        assert!(converts_editor_on_switch("text", "hex"));
        assert!(converts_editor_on_switch("hex", "text"));
    }
}
