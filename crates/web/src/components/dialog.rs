//! A modal confirmation dialog on the native `<dialog>` element. Opened
//! with `showModal()`, the browser moves focus into it, makes the rest of
//! the page inert, closes it on Escape, and returns focus to the button
//! that opened it.

use leptos::{html, prelude::*};

/// The open dialog, for [`DialogCancel`] inside it.
#[derive(Clone, Copy)]
struct DialogHandle(NodeRef<html::Dialog>);

fn close(dialog: NodeRef<html::Dialog>) {
    if let Some(dialog) = dialog.get() {
        dialog.close();
    }
}

/// A button labelled `trigger` that opens a dialog titled `title` around
/// `children`, usually an action form with a [`DialogCancel`] next to its
/// submit button. Submitting a form inside closes the dialog, so the
/// outcome shows on the page behind it.
#[component]
pub fn ConfirmDialog(
    #[prop(into)] trigger: String,
    #[prop(into)] title: String,
    children: Children,
) -> impl IntoView {
    let dialog = NodeRef::<html::Dialog>::new();
    provide_context(DialogHandle(dialog));
    let open = move |_| {
        if let Some(dialog) = dialog.get() {
            // Fails only when the dialog is already open or detached.
            let _ = dialog.show_modal();
        }
    };
    let label = title.clone();
    view! {
        <button type="button" class="button dialog-trigger" aria-haspopup="dialog" on:click=open>{trigger}</button>
        <dialog class="dialog" aria-label=label node_ref=dialog on:submit=move |_| close(dialog)>
            <h2 class="dialog-title">{title}</h2>
            {children()}
        </dialog>
    }
}

/// Closes the surrounding [`ConfirmDialog`] without doing anything.
#[component]
pub fn DialogCancel() -> impl IntoView {
    let handle = use_context::<DialogHandle>();
    view! {
        <button
            type="button"
            class="button"
            on:click=move |_| {
                if let Some(DialogHandle(dialog)) = handle {
                    close(dialog);
                }
            }
        >
            "Cancel"
        </button>
    }
}
